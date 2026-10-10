//go:build linux

package releasebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
)

// These structs decode the Go tool's external JSON protocol, not product config.
type goModule struct {
	Path, Version, Sum string
	Replace            *goModule
}
type goPackage struct {
	ImportPath string
	Imports    []string
	Module     *goModule
	Standard   bool
}

func sbom(ctx context.Context, source string, environment []string, product, version, arch string, npmDocument []byte) ([]byte, error) {
	data, err := command(ctx, source, environment, "go", "list", "-mod=readonly", "-deps", "-json", "./cmd/"+product)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	packages := map[string]goPackage{}
	modules := map[string]*goModule{}
	packageModule := map[string]string{}
	root := "pkg:generic/" + product + "@" + version + "?arch=" + arch
	for {
		var p goPackage
		if err := decoder.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		packages[p.ImportPath] = p
		if p.Module == nil {
			continue
		}
		m := p.Module
		if m.Replace != nil {
			m = m.Replace
			if m.Version == "" {
				return nil, errors.New("releasebuild: local Go replacements are not portable release inputs")
			}
		}
		ref := root
		if m.Path != "lindm" {
			ref = "pkg:golang/" + m.Path + "@" + url.PathEscape(m.Version)
			modules[ref] = m
		}
		packageModule[p.ImportPath] = ref
	}
	edges := map[string]map[string]bool{root: {}}
	for name, p := range packages {
		from := packageModule[name]
		if from == "" {
			continue
		}
		if edges[from] == nil {
			edges[from] = map[string]bool{}
		}
		for _, dependency := range p.Imports {
			to := packageModule[dependency]
			if to != "" && to != from {
				edges[from][to] = true
			}
		}
	}
	refs := make([]string, 0, len(modules))
	for ref := range modules {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	components := []any{}
	for _, ref := range refs {
		m := modules[ref]
		component := map[string]any{"type": "library", "bom-ref": ref, "name": m.Path, "version": m.Version, "purl": ref, "properties": []any{map[string]string{"name": "lindm:go:module-sum", "value": m.Sum}}}
		components = append(components, component)
	}
	dependencies := []any{}
	refs = refs[:0]
	for ref := range edges {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		children := []string{}
		for child := range edges[ref] {
			children = append(children, child)
		}
		sort.Strings(children)
		dependencies = append(dependencies, map[string]any{"ref": ref, "dependsOn": children})
	}
	if product == "lindmd" {
		var npm map[string]json.RawMessage
		if err := json.Unmarshal(npmDocument, &npm); err != nil {
			return nil, err
		}
		var npmComponents, npmDependencies []any
		if err := json.Unmarshal(npm["components"], &npmComponents); err != nil {
			return nil, fmt.Errorf("releasebuild: npm SBOM components: %w", err)
		}
		if err := json.Unmarshal(npm["dependencies"], &npmDependencies); err != nil {
			return nil, fmt.Errorf("releasebuild: npm SBOM graph: %w", err)
		}
		var metadata struct {
			Component map[string]any `json:"component"`
		}
		if err := json.Unmarshal(npm["metadata"], &metadata); err != nil {
			return nil, err
		}
		npmRoot, ok := metadata.Component["bom-ref"].(string)
		if !ok || npmRoot == "" {
			return nil, errors.New("releasebuild: npm SBOM root missing")
		}
		components = append(components, metadata.Component)
		components = append(components, npmComponents...)
		dependencies = append(dependencies, npmDependencies...)
		// The console is built into lindmd; the npm root is an actual product input.
		for _, item := range dependencies {
			if edge, ok := item.(map[string]any); ok && edge["ref"] == root {
				children, ok := edge["dependsOn"].([]string)
				if !ok {
					return nil, errors.New("releasebuild: invalid Go SBOM dependency edge")
				}
				edge["dependsOn"] = append(children, npmRoot)
			}
		}
	}
	return json.MarshalIndent(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": map[string]any{"component": map[string]any{"type": "application", "bom-ref": root, "name": product, "version": version, "purl": root}, "properties": []any{map[string]string{"name": "lindm:scope", "value": "linked Go module graph; lindmd also includes the actual npm build graph (including build tools); no inferred license declarations"}}}, "components": components, "dependencies": dependencies}, "", "  ")
}

func withCABundleSBOM(encoded []byte, digest string) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		return nil, err
	}
	var components []json.RawMessage
	if err := json.Unmarshal(document["components"], &components); err != nil {
		return nil, err
	}
	reference := "urn:sha256:" + digest
	component, err := json.Marshal(map[string]any{"type": "file", "bom-ref": reference, "name": "/etc/ssl/certs/ca-certificates.crt", "hashes": []any{map[string]string{"alg": "SHA-256", "content": digest}}, "properties": []any{map[string]string{"name": "lindm:trust-source", "value": "explicit independently digest-pinned CA bundle; no ambient host roots"}}})
	if err != nil {
		return nil, err
	}
	components = append(components, component)
	document["components"], err = json.Marshal(components)
	if err != nil {
		return nil, err
	}
	var metadata struct {
		Component struct {
			Reference string `json:"bom-ref"`
		} `json:"component"`
	}
	if err := json.Unmarshal(document["metadata"], &metadata); err != nil {
		return nil, err
	}
	var dependencies []struct {
		Reference string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	}
	if err := json.Unmarshal(document["dependencies"], &dependencies); err != nil {
		return nil, err
	}
	found := false
	for i := range dependencies {
		if dependencies[i].Reference == metadata.Component.Reference {
			dependencies[i].DependsOn = append(dependencies[i].DependsOn, reference)
			found = true
		}
	}
	if !found {
		return nil, errors.New("releasebuild: SBOM product dependency root missing")
	}
	document["dependencies"], err = json.Marshal(dependencies)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(document, "", "  ")
}
