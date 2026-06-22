use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsStr,
    fmt, path,
};

use parser::ast::{BuildConstraintExprNode, SourceFileNode};

/// Default cap on the number of free build-tag dimensions to enumerate.
///
/// With `2^N` permutations to explore, 8 already produces 256 worlds:
/// anything larger is impractical and is well past anything observed in most
/// real-world Go projects.
pub const DEFAULT_MAX_BUILD_TAG_DIMENSIONS: usize = 8;

// we know that exactly one of these is active at a time (discard other worlds)
const KNOWN_COMPILER_VALUES: &[&str] = &["gc", "gccgo"];

// we know that exactly one of these is active at a time (discard other worlds)
const KNOWN_GOOS_VALUES: &[&str] = &[
    "aix",
    "android",
    "darwin",
    "dragonfly",
    "freebsd",
    "hurd",
    "illumos",
    "ios",
    "js",
    "linux",
    "nacl",
    "netbsd",
    "openbsd",
    "plan9",
    "solaris",
    "wasip1",
    "windows",
    "zos",
];

// we know that exactly one of these is active at a time (discard other worlds)
const KNOWN_GOARCH_VALUES: &[&str] = &[
    "386",
    "amd64",
    "amd64p32",
    "arm",
    "arm64",
    "arm64be",
    "armbe",
    "loong64",
    "mips",
    "mips64",
    "mips64le",
    "mips64p32",
    "mips64p32le",
    "mipsle",
    "ppc",
    "ppc64",
    "ppc64le",
    "riscv",
    "riscv64",
    "s390",
    "s390x",
    "sparc",
    "sparc64",
    "wasm",
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActiveTags<'a>(BTreeSet<&'a str>);

#[derive(Debug)]
pub struct BuildPermutation<'a> {
    // multiple ActiveTags might result in the same files being admitted, hence
    // the use of a BTreeSet; otherwise we would generate identical permutations
    pub tag_sets: BTreeSet<ActiveTags<'a>>,
    pub admitted: BTreeSet<&'a path::Path>,
}

impl<'a> ActiveTags<'a> {
    fn new(tags: impl IntoIterator<Item = &'a str>) -> Self {
        Self(tags.into_iter().collect())
    }

    pub fn contains(&self, tag: &str) -> bool {
        self.0.contains(tag)
    }

    pub fn iter(&self) -> impl Iterator<Item = &'a str> {
        self.0.iter().copied()
    }

    fn admits_file(
        &self,
        virtual_path: &'a path::Path,
        ast: &SourceFileNode<'a>,
        include_tests: bool,
    ) -> bool {
        let Some(filename) = virtual_path.file_name().and_then(OsStr::to_str) else {
            return false;
        };

        if !include_tests && is_test_file(filename) {
            return false;
        }

        if let Some(constraint) = implicit_tags_from_filename(filename)
            && constraint.iter().any(|tag| !self.contains(tag))
        {
            return false;
        }

        if let Some(constraint) = &ast.build_constraint
            && !self.evaluate_expr(&constraint.expr)
        {
            return false;
        }

        true
    }

    fn evaluate_expr(&self, expr: &BuildConstraintExprNode<'a>) -> bool {
        match expr {
            BuildConstraintExprNode::Tag(name) => is_go_version_tag(name) || self.contains(name),
            BuildConstraintExprNode::Not(inner) => !self.evaluate_expr(inner),
            BuildConstraintExprNode::And(clauses) => {
                clauses.iter().all(|clause| self.evaluate_expr(clause))
            }
            BuildConstraintExprNode::Or(clauses) => {
                clauses.iter().any(|clause| self.evaluate_expr(clause))
            }
        }
    }
}

impl fmt::Display for ActiveTags<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.iter().collect::<Vec<_>>().join(", "))
    }
}

pub fn enumerate_build_permutations<'a>(
    parsed: &BTreeMap<&'a path::Path, SourceFileNode<'a>>,
    include_tests: bool,
    max_dimensions: usize,
) -> Result<Vec<BuildPermutation<'a>>, BTreeSet<&'a str>> {
    // start by removing from the pool entirely all the files with an `ignore`
    // build tag constraint, which by convention is only required by files that
    // should never be included (e.g., scripts to generate source code)
    let not_ignored: BTreeMap<&'a path::Path, &SourceFileNode<'a>> = parsed
        .iter()
        .filter(|(_, ast)| {
            ast.build_constraint
                .as_ref()
                .is_none_or(|constraint| !should_ignore(&constraint.expr))
        })
        .map(|(path, ast)| (*path, ast))
        .collect();

    let mentioned = collect_mentioned_tags(not_ignored.iter().map(|(p, a)| (*p, *a)));

    if mentioned.len() > max_dimensions {
        return Err(mentioned);
    }

    let free_dims: Vec<&'a str> = mentioned.iter().copied().collect();

    let mut buckets: HashMap<BTreeSet<&'a path::Path>, BTreeSet<ActiveTags<'a>>> = HashMap::new();

    for mask in 0..(1_usize << free_dims.len()) {
        let world: Vec<&'a str> = free_dims
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, t)| *t)
            .collect();

        if world.iter().filter(|tag| is_known_goos(tag)).count() > 1
            || world.iter().filter(|tag| is_known_goarch(tag)).count() > 1
            || world.iter().filter(|tag| is_known_compiler(tag)).count() > 1
        {
            // we know that these values only allow at most one of them at a
            // time, so we are free to discard all permutation worlds where
            // e.g. multiple architectures/compilers are being targeted at once
            continue;
        }

        let tags = ActiveTags::new(world.iter().copied());

        let admitted: BTreeSet<&'a path::Path> = not_ignored
            .iter()
            .filter(|(path, ast)| tags.admits_file(path, ast, include_tests))
            .map(|(path, _)| *path)
            .collect();

        if admitted.is_empty() {
            // this permutation applies to 0 files, so we are free to skip it
            continue;
        }

        buckets.entry(admitted).or_default().insert(tags);
    }

    let mut ordered: Vec<_> = buckets
        .into_iter()
        .map(|(admitted, tag_sets)| BuildPermutation { tag_sets, admitted })
        .collect();

    ordered.sort_by_cached_key(|perm| perm.tag_sets.clone());

    Ok(ordered)
}

pub fn always_active_tags<'a>(perms: &[BuildPermutation<'a>]) -> BTreeSet<&'a str> {
    let mut all_tag_sets = perms.iter().flat_map(|p| p.tag_sets.iter());

    let Some(first) = all_tag_sets.next() else {
        return BTreeSet::new();
    };

    all_tag_sets.fold(first.0.clone(), |acc, tags| {
        acc.intersection(&tags.0).copied().collect()
    })
}

fn should_ignore(expr: &BuildConstraintExprNode<'_>) -> bool {
    // the `ignore` tag is never satisfied, by convention

    match expr {
        BuildConstraintExprNode::Tag("ignore") => true,
        BuildConstraintExprNode::Tag(_) | BuildConstraintExprNode::Not(_) => {
            // the Tag case (for anything but "ignore") is trivially false

            // regarding the Not case:
            // counterintuitively, we should not return `!should_ignore(inner)`:
            // if inner requires "ignore", negating it means we shouldn't ignore
            // and if inner does not require "ignore", negating it also means we
            // should not ignore the file

            false
        }
        BuildConstraintExprNode::And(clauses) => clauses.iter().any(should_ignore),
        BuildConstraintExprNode::Or(clauses) => clauses.iter().all(should_ignore),
    }
}

fn collect_mentioned_tags<'a: 'b, 'b>(
    parsed: impl IntoIterator<Item = (&'a path::Path, &'b SourceFileNode<'a>)>,
) -> BTreeSet<&'a str> {
    let mut mentioned: BTreeSet<&'a str> = BTreeSet::new();

    for (path, ast) in parsed {
        if let Some(constraint) = &ast.build_constraint {
            collect_tags_in_expr(&constraint.expr, &mut mentioned);
        }

        if let Some(filename) = path.file_name().and_then(OsStr::to_str)
            && let Some(tags) = implicit_tags_from_filename(filename)
        {
            mentioned.extend(tags);
        }
    }

    mentioned
}

fn collect_tags_in_expr<'a>(expr: &BuildConstraintExprNode<'a>, mentioned: &mut BTreeSet<&'a str>) {
    match expr {
        BuildConstraintExprNode::Tag(name) if is_go_version_tag(name) => {} // ignore
        BuildConstraintExprNode::Tag(name) => {
            mentioned.insert(name);
        }
        BuildConstraintExprNode::Not(inner) => collect_tags_in_expr(inner, mentioned),
        BuildConstraintExprNode::And(clauses) | BuildConstraintExprNode::Or(clauses) => {
            for clause in clauses {
                collect_tags_in_expr(clause, mentioned);
            }
        }
    }
}

fn implicit_tags_from_filename(filename: &str) -> Option<Vec<&str>> {
    let stem = filename.strip_suffix(".go")?;
    let stem = stem.strip_suffix("_test").unwrap_or(stem);

    let (head, last) = stem.rsplit_once('_')?;

    // prefer the more specific `_GOOS_GOARCH` form, but only when the two
    // trailing segments really do name a valid (GOOS, GOARCH) pair *and*
    // there's a non-empty prefix before them.
    if let Some((prefix, mid)) = head.rsplit_once('_')
        && !prefix.is_empty()
        && is_known_goos(mid)
        && is_known_goarch(last)
    {
        return Some(vec![mid, last]);
    }

    if !head.is_empty() && (is_known_goos(last) || is_known_goarch(last)) {
        return Some(vec![last]);
    }

    None
}

fn is_test_file(filename: &str) -> bool {
    filename.ends_with("_test.go")
}

fn is_known_compiler(name: &str) -> bool {
    KNOWN_COMPILER_VALUES.contains(&name)
}

fn is_known_goos(name: &str) -> bool {
    KNOWN_GOOS_VALUES.contains(&name)
}

fn is_known_goarch(name: &str) -> bool {
    KNOWN_GOARCH_VALUES.contains(&name)
}

fn is_go_version_tag(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("go") else {
        return false;
    };

    let Some((major, minor)) = rest.split_once('.') else {
        return false;
    };

    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && minor.bytes().all(|b| b.is_ascii_digit())
}
