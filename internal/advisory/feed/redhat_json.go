package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"buf.build/go/protovalidate"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

const (
	redHatScalarBytes = 64 << 10
	redHatTreeBytes   = 64 << 20
	redHatJSONDepth   = 64
)

// redHatJSONReader bounds individual tokens before json.Decoder can allocate
// them, and rejects invalid UTF-8 rather than accepting Decoder's replacement
// characters. All bytes, including ignored fields, pass through this reader.
type redHatJSONReader struct {
	reader    io.Reader
	quoted    bool
	escaped   bool
	tokenSize int
	pending   [utf8.UTFMax]byte
	pendingN  int
}

func (r *redHatJSONReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	for _, b := range p[:n] {
		if r.pendingN != 0 || b >= utf8.RuneSelf {
			r.pending[r.pendingN] = b
			r.pendingN++
			if utf8.FullRune(r.pending[:r.pendingN]) {
				value, size := utf8.DecodeRune(r.pending[:r.pendingN])
				if value == utf8.RuneError && size == 1 {
					return 0, errors.New("feed: Red Hat CSAF is not UTF-8")
				}
				r.pendingN = 0
			}
		}
		if r.quoted {
			r.tokenSize++
			if r.escaped {
				r.escaped = false
			} else if b == '\\' {
				r.escaped = true
			} else if b == '"' {
				r.quoted = false
				r.tokenSize = 0
			}
		} else {
			switch b {
			case '"':
				r.quoted = true
				r.tokenSize = 0
			case ' ', '\t', '\r', '\n', '{', '}', '[', ']', ':', ',':
				r.tokenSize = 0
			default:
				r.tokenSize++
			}
		}
		if r.tokenSize > redHatScalarBytes {
			return 0, errors.New("feed: Red Hat JSON scalar byte limit")
		}
	}
	if err == io.EOF && r.pendingN != 0 {
		return 0, errors.New("feed: Red Hat CSAF is not UTF-8")
	}
	return n, err
}

type redHatJSON struct {
	decoder *json.Decoder
	depth   int
}

func (j *redHatJSON) container(open json.Delim, visit func(string) error) error {
	token, err := j.decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return nil
	}
	if token != open {
		return fmt.Errorf("feed: Red Hat JSON requires %c", open)
	}
	return j.contents(open, visit)
}

func (j *redHatJSON) contents(open json.Delim, visit func(string) error) error {
	j.depth++
	defer func() { j.depth-- }()
	if j.depth > redHatJSONDepth {
		return errors.New("feed: Red Hat JSON depth limit")
	}
	var seen map[string]bool
	if open == '{' && visit != nil {
		seen = make(map[string]bool)
	}
	for count := 0; j.decoder.More(); count++ {
		if count >= maxEntries {
			return errors.New("feed: Red Hat JSON container entry limit")
		}
		key := ""
		if open == '{' {
			token, err := j.decoder.Token()
			if err != nil {
				return err
			}
			var ok bool
			key, ok = token.(string)
			if !ok {
				return errors.New("feed: Red Hat JSON object key required")
			}
			if seen != nil {
				if seen[key] || len(seen) >= 128 {
					return errors.New("feed: duplicate or excessive Red Hat JSON object keys")
				}
				seen[key] = true
			}
		}
		if visit == nil {
			if err := j.skip(); err != nil {
				return err
			}
		} else if err := visit(key); err != nil {
			return err
		}
	}
	close := json.Delim(']')
	if open == '{' {
		close = '}'
	}
	token, err := j.decoder.Token()
	if err != nil {
		return err
	}
	if token != close {
		return errors.New("feed: incomplete Red Hat JSON container")
	}
	return nil
}

func (j *redHatJSON) skip() error {
	token, err := j.decoder.Token()
	if err != nil {
		return err
	}
	if open, ok := token.(json.Delim); ok {
		if open != '{' && open != '[' {
			return errors.New("feed: unexpected Red Hat JSON delimiter")
		}
		return j.contents(open, nil)
	}
	return nil
}

func (j *redHatJSON) text(dst *string) error {
	token, err := j.decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return nil
	}
	value, ok := token.(string)
	if !ok {
		return errors.New("feed: Red Hat JSON string required")
	}
	*dst = value
	return nil
}

func (j *redHatJSON) product(destination **suseProduct) error {
	token, err := j.decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return nil
	}
	if token != json.Delim('{') {
		return errors.New("feed: Red Hat product object required")
	}
	product := new(suseProduct)
	*destination = product
	return j.contents('{', func(key string) error {
		switch key {
		case "product_id":
			return j.text(&product.ID)
		case "name":
			return j.text(&product.Name)
		case "product_identification_helper":
			return j.container('{', func(key string) error {
				switch key {
				case "cpe":
					return j.text(&product.Helper.CPE)
				case "purl":
					return j.text(&product.Helper.PURL)
				default:
					return j.skip()
				}
			})
		default:
			return j.skip()
		}
	})
}

func (j *redHatJSON) document(notice *suseCSAF) error {
	d := &notice.Document
	return j.container('{', func(key string) error {
		switch key {
		case "category":
			return j.text(&d.Category)
		case "csaf_version":
			return j.text(&d.Version)
		case "publisher":
			return j.container('{', func(key string) error {
				switch key {
				case "category":
					return j.text(&d.Publisher.Category)
				case "namespace":
					return j.text(&d.Publisher.Namespace)
				default:
					return j.skip()
				}
			})
		case "aggregate_severity":
			return j.container('{', func(key string) error {
				if key == "text" {
					return j.text(&d.Severity.Text)
				}
				return j.skip()
			})
		case "tracking":
			return j.container('{', func(key string) error {
				switch key {
				case "id":
					return j.text(&d.Tracking.ID)
				case "status":
					return j.text(&d.Tracking.Status)
				case "initial_release_date":
					return j.text(&d.Tracking.Published)
				default:
					return j.skip()
				}
			})
		default:
			return j.skip()
		}
	})
}

// Parent indices preserve branch inheritance when children precede category,
// name or product in the JSON object. No recursive RawMessage is retained.
type redHatBranch struct {
	parent      int
	category    string
	name        string
	product     *suseProduct
	arch        string
	unsupported bool
}

type redHatTree struct {
	branches         []redHatBranch
	relations        map[string]suseRelationship
	unsupported      bool
	invalidRelations bool
	textBytes        int
}

func (tree *redHatTree) retain(size int) error {
	tree.textBytes += size
	if tree.textBytes > redHatTreeBytes {
		return errors.New("feed: Red Hat product metadata byte limit")
	}
	return nil
}

func redHatProductBytes(product suseProduct) int {
	return len(product.ID) + len(product.Name) + len(product.Helper.CPE) + len(product.Helper.PURL)
}

func (j *redHatJSON) branches(tree *redHatTree, parent, depth int) error {
	if depth > 12 {
		return errors.New("feed: Red Hat product tree depth limit")
	}
	return j.container('[', func(string) error {
		if len(tree.branches) >= maxEntries {
			return errors.New("feed: Red Hat product tree entry limit")
		}
		index := len(tree.branches)
		tree.branches = append(tree.branches, redHatBranch{parent: parent})
		if err := j.container('{', func(key string) error {
			switch key {
			case "category":
				return j.text(&tree.branches[index].category)
			case "name":
				return j.text(&tree.branches[index].name)
			case "product":
				var product *suseProduct
				if err := j.product(&product); err != nil {
					return err
				}
				if product == nil {
					return nil
				}
				tree.branches[index].product = product
				return tree.retain(redHatProductBytes(*product))
			case "branches":
				return j.branches(tree, index, depth+1)
			default:
				return j.skip()
			}
		}); err != nil {
			return err
		}
		return tree.retain(len(tree.branches[index].category) + len(tree.branches[index].name))
	})
}

func (j *redHatJSON) tree(tree *redHatTree) error {
	return j.container('{', func(key string) error {
		switch key {
		case "branches":
			return j.branches(tree, -1, 0)
		case "relationships":
			return j.container('[', func(string) error {
				var relation suseRelationship
				if err := j.container('{', func(key string) error {
					switch key {
					case "category":
						return j.text(&relation.Category)
					case "product_reference":
						return j.text(&relation.Component)
					case "relates_to_product_reference":
						return j.text(&relation.Platform)
					case "full_product_name":
						var product *suseProduct
						if err := j.product(&product); err != nil {
							return err
						}
						if product != nil {
							relation.Product = *product
						}
						return nil
					default:
						return j.skip()
					}
				}); err != nil {
					return err
				}
				if _, duplicate := tree.relations[relation.Product.ID]; duplicate || relation.Product.ID == "" {
					tree.invalidRelations = true
				}
				if err := tree.retain(len(relation.Category) + len(relation.Component) + len(relation.Platform) + redHatProductBytes(relation.Product)); err != nil {
					return err
				}
				tree.relations[relation.Product.ID] = relation
				return nil
			})
		case "full_product_names", "product_groups":
			return j.container('[', func(string) error {
				tree.unsupported = true
				return j.skip()
			})
		default:
			return j.skip()
		}
	})
}

func (tree *redHatTree) products() (map[string]redHatProduct, error) {
	products := make(map[string]redHatProduct)
	roots := 0
	for index := range tree.branches {
		branch := &tree.branches[index]
		if branch.parent == -1 {
			roots++
			if roots != 1 || branch.category != "vendor" {
				return nil, errors.New("feed: Red Hat requires one explicit vendor root")
			}
		} else {
			parent := &tree.branches[branch.parent]
			branch.arch, branch.unsupported = parent.arch, parent.unsupported
		}
		switch branch.category {
		case "vendor":
			if branch.parent != -1 || branch.name != "Red Hat" {
				return nil, errors.New("feed: unsupported Red Hat product vendor")
			}
		case "product_family", "product_name", "product_version":
		case "architecture":
			if branch.arch != "" {
				return nil, errors.New("feed: nested Red Hat architecture")
			}
			branch.arch = canonicalArch(branch.name)
		default:
			branch.unsupported = true
		}
		if p := branch.product; p != nil {
			if p.ID == "" || p.Name == "" {
				return nil, errors.New("feed: invalid Red Hat product")
			}
			if previous, duplicate := products[p.ID]; duplicate {
				// Off-scope duplicate legacy module builds remain irrelevant;
				// relevant relationships must reject their ambiguous identity.
				previous.unsupported = true
				products[p.ID] = previous
			} else {
				products[p.ID] = redHatProduct{product: *p, arch: branch.arch, unsupported: branch.unsupported}
			}
		}
	}
	if roots != 1 {
		return nil, errors.New("feed: Red Hat requires one explicit vendor root")
	}
	tree.branches = nil
	return products, nil
}

type redHatVulnerability struct {
	CVE    string
	Status map[string][]string
}

func (j *redHatJSON) vulnerability(v *redHatVulnerability) error {
	v.Status = make(map[string][]string)
	count, size := 0, 0
	return j.container('{', func(key string) error {
		switch key {
		case "cve":
			return j.text(&v.CVE)
		case "product_status":
			return j.container('{', func(status string) error {
				return j.container('[', func(string) error {
					var id string
					if err := j.text(&id); err != nil {
						return err
					}
					count++
					size += len(id)
					if count > maxEntries || size > redHatTreeBytes {
						return errors.New("feed: Red Hat vulnerability status limit")
					}
					v.Status[status] = append(v.Status[status], id)
					return nil
				})
			})
		default:
			return j.skip()
		}
	})
}

// parseRedHatClaims stages at most one original document on disk. Its first
// token pass validates the entire JSON and builds the bounded product index;
// the second seeks to vulnerabilities, processing only one at a time. Callers
// stage claims, and must discard the entire generation on any returned error.
func parseRedHatClaims(ctx context.Context, config *advisoryv1.FeedSource, input io.Reader, validator protovalidate.Validator, emit func(*advisoryv1.Advisory) error) (err error) {
	if err := redHatConfig(config); err != nil {
		return err
	}
	file, err := os.CreateTemp("", "lindm-redhat-json-*")
	if err != nil {
		return fmt.Errorf("feed: stage Red Hat JSON: %w", err)
	}
	defer func() { err = errors.Join(err, file.Close(), os.Remove(file.Name())) }()
	if err := copyArchive(ctx, file, input, redHatRecordBytes); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return parseRedHatFile(ctx, config, file, validator, emit)
}

func parseRedHatFile(ctx context.Context, config *advisoryv1.FeedSource, file *os.File, validator protovalidate.Validator, emit func(*advisoryv1.Advisory) error) error {
	j := &redHatJSON{decoder: json.NewDecoder(&redHatJSONReader{reader: contextFeedReader{ctx, file}})}
	j.decoder.UseNumber()
	var notice suseCSAF
	tree := redHatTree{relations: make(map[string]suseRelationship)}
	var vulnerabilities int64 = -1
	vulnerabilitiesPresent := false
	if err := j.container('{', func(key string) error {
		switch key {
		case "document":
			return j.document(&notice)
		case "product_tree":
			return j.tree(&tree)
		case "vulnerabilities":
			vulnerabilitiesPresent = true
			token, err := j.decoder.Token()
			if err != nil {
				return err
			}
			if token == nil {
				return nil
			}
			if token != json.Delim('[') {
				return errors.New("feed: Red Hat vulnerabilities array required")
			}
			vulnerabilities = j.decoder.InputOffset() - 1
			return j.contents('[', nil)
		default:
			return j.skip()
		}
	}); err != nil {
		return fmt.Errorf("feed: decode Red Hat CSAF: %w", err)
	}
	if _, err := j.decoder.Token(); err != io.EOF {
		return errors.New("feed: trailing or malformed Red Hat JSON")
	}
	products, err := tree.products()
	if err != nil {
		return err
	}
	potential := false
	for _, product := range products {
		if applies, _ := redHatPlatform(config, product.product, "under_investigation"); applies {
			potential = true
			break
		}
	}
	// Signed distributions also contain historical informational advisories.
	// Product CPEs independently establish scope; an off-scope document cannot
	// supply claims and need not satisfy the selected product's advisory policy.
	// Applicable documents still undergo every metadata and status check.
	if !potential {
		return errRedHatNotApplicable
	}
	d := &notice.Document
	if d.Version != "2.0" || (d.Category != "csaf_security_advisory" && d.Category != "csaf_vex" && d.Category != "csaf_informational_advisory") || d.Tracking.Status != "final" || d.Publisher.Category != "vendor" || d.Publisher.Namespace != "https://www.redhat.com" {
		return errors.New("feed: unsupported Red Hat CSAF document or publisher")
	}
	if _, err := timestamp(d.Tracking.Published); err != nil {
		return err
	}
	if tree.unsupported {
		return errors.New("feed: unsupported Red Hat standalone products or groups")
	}
	if tree.invalidRelations {
		return errors.New("feed: unsupported or duplicate Red Hat relationship")
	}
	for id := range tree.relations {
		if _, collision := products[id]; collision {
			return errors.New("feed: unsupported or duplicate Red Hat relationship")
		}
	}
	if d.Category == "csaf_informational_advisory" {
		// CSAF 2.0 profile 3 (§4.3/§6.1.27.3) forbids the property itself,
		// including null or an empty array. Genuine RHSA-2023:6529 follows
		// this profile: its RHEL 9 AppStream update supplies no CVE claims.
		if vulnerabilitiesPresent {
			return errors.New("feed: Red Hat informational advisory contains vulnerabilities")
		}
		return errRedHatNotApplicable
	}
	if vulnerabilities == -1 {
		return errRedHatNotApplicable
	}
	if _, err := file.Seek(vulnerabilities, io.SeekStart); err != nil {
		return err
	}
	j = &redHatJSON{decoder: json.NewDecoder(contextFeedReader{ctx, file})}
	j.decoder.UseNumber()
	count := 0
	if err := j.container('[', func(string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var vulnerability redHatVulnerability
		if err := j.vulnerability(&vulnerability); err != nil {
			return err
		}
		return redHatVulnerabilityClaims(config, &notice, vulnerability, products, tree.relations, validator, func(record *advisoryv1.Advisory) error {
			count++
			return emit(record)
		})
	}); err != nil {
		return err
	}
	if count == 0 {
		return errRedHatNotApplicable
	}
	return nil
}
