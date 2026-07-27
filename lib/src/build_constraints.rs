use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsStr,
    fmt, path,
};

use parser::ast::{BuildConstraintExprNode, SourceFileNode};

/// Default cap on the number of distinct build permutations to analyze.
///
/// This applies after permutation deduplication, i.e., it only counts once any
/// number of build-tag constraints which collapse to the same set of ultimately
/// admitted files.
///
/// Anything larger than 256 worlds is impractical and is well past anything
/// observed in the vast majority of real-world Go projects.
pub const DEFAULT_MAX_BUILD_PERMUTATIONS: usize = 256;

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

    fn admits_file(&self, virtual_path: &'a path::Path, ast: &SourceFileNode<'a>) -> bool {
        let Some(filename) = virtual_path.file_name().and_then(OsStr::to_str) else {
            return false;
        };

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
            BuildConstraintExprNode::Tag(name) => {
                !is_conventional_ignore_tag(name)
                    && (is_go_version_tag(name) || self.contains(name))
            }
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
    max_permutations: usize,
) -> Result<Vec<BuildPermutation<'a>>, usize> {
    // start by removing from the pool entirely all the files whose build
    // constraint can never be satisfied because it requires a conventional
    // ignore tag, which should only be required by files that ought never be
    // included in normal builds (e.g., scripts to generate source code)
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
    let free_dims: Vec<&'a str> = mentioned.iter().copied().collect();

    let mut buckets: HashMap<BTreeSet<&'a path::Path>, BTreeSet<ActiveTags<'a>>> = HashMap::new();
    let mut enabled = vec![false; free_dims.len()];
    // ^ we don't use a numeric bitmask to avoid potential problems with
    // overflow if there are more than 64 tags before deduplication

    loop {
        let world: Vec<&'a str> = free_dims
            .iter()
            .zip(&enabled)
            .filter(|(_, enabled)| **enabled)
            .map(|(tag, _)| *tag)
            .collect();

        if world.iter().filter(|tag| is_known_goos(tag)).count() > 1
            || world.iter().filter(|tag| is_known_goarch(tag)).count() > 1
            || world.iter().filter(|tag| is_known_compiler(tag)).count() > 1
        {
            // we know that these values only allow at most one of them at a
            // time, so we are free to discard all permutation worlds where
            // e.g. multiple architectures/compilers are being targeted at once
        } else {
            let tags = ActiveTags::new(world.iter().copied());

            let admitted: BTreeSet<&'a path::Path> = not_ignored
                .iter()
                .filter(|(path, ast)| tags.admits_file(path, ast))
                .map(|(path, _)| *path)
                .collect();

            if !admitted.is_empty() {
                buckets.entry(admitted).or_default().insert(tags);
            }
        }

        if !advance_assignment(&mut enabled) {
            break;
        }
    }

    // we only check against the limit so we can report an accurate "real" count
    if buckets.len() > max_permutations {
        return Err(buckets.len());
    }

    let mut ordered: Vec<_> = buckets
        .into_iter()
        .map(|(admitted, tag_sets)| BuildPermutation { tag_sets, admitted })
        .collect();

    ordered.sort_by_cached_key(|perm| perm.tag_sets.clone());

    Ok(ordered)
}

fn advance_assignment(enabled: &mut [bool]) -> bool {
    for bit in enabled {
        if *bit {
            *bit = false;
        } else {
            *bit = true;

            return true;
        }
    }

    false
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
    match expr {
        BuildConstraintExprNode::Tag(name) => is_conventional_ignore_tag(name),
        BuildConstraintExprNode::Not(_) => {
            // counterintuitively, we should not return `!should_ignore(inner)`:
            // if inner requires an ignore tag, negating it means we shouldn't
            // ignore (makes the constraint satisfiable) and if inner does not
            // require "ignore", negating it also means we should not ignore the
            // file, so in both cases we just return `false`

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
        BuildConstraintExprNode::Tag(name)
            if is_go_version_tag(name) || is_conventional_ignore_tag(name) => {} // ignore
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

fn is_conventional_ignore_tag(name: &str) -> bool {
    // by convention, `ignore` is never satisfied, but we extend this further by
    // considering as an ignore tag any tag containing the word `ignore`, since
    // sometimes e.g. `ignore_autogenerated` is used by some projects

    name.split(|ch: char| !ch.is_alphanumeric())
        .any(|word| word == "ignore")
}
