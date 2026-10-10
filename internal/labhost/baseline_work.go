package labhost

// baselineWorkScript never changes existing ancestor permissions: a shared
// group-writable work parent must instead be replaced in the host configuration.
func baselineWorkScript(work string) string {
	return "umask 077\nwork=" + baselineQuote(work) + `
created=false
if [[ ! -e $work && ! -L $work ]]; then
  mkdir -p -- "$work"
  created=true
fi
printf '%s\n' "$created"
[[ -d $work && ! -L $work && -O $work && $(stat -c %a -- "$work") == 700 ]] || { echo 'baseline work directory must be a real run-user-owned mode-0700 directory' >&2; exit 1; }
parent=$work
while :; do
  [[ ! -L $parent ]] || { echo 'baseline work ancestry must not contain symlinks' >&2; exit 1; }
  read -r mode owner < <(stat -c '%a %u' -- "$parent")
  [[ $owner == 0 || $owner == "$UID" ]] || { echo 'baseline work ancestry is not owned by root or the run user' >&2; exit 1; }
  mode=$((8#$mode))
  (( (mode & 0022) == 0 || (mode & 01000) != 0 )) || { echo 'baseline work ancestry is writable by another user; choose a private work directory' >&2; exit 1; }
  [[ $parent == / ]] && break
  parent=$(dirname -- "$parent")
done
`
}
