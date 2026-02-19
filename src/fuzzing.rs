use std::fs;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;

/// Persists an input into `fuzz/corpus/<target>/` using a content hash filename.
///
/// Duplicate inputs naturally dedupe because they produce the same hash/path.
pub fn fuzz_write_into_corpus(target: &str, input: &[u8]) -> Result<PathBuf> {
    if target.is_empty()
        || !target
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "fuzz target name must be non-empty and filesystem-safe",
        ));
    }

    let root = std::env::var("LEASH_FUZZ_CORPUS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus"));
    let dir = root.join(target);
    fs::create_dir_all(&dir)?;

    let filename = format!("{}.bin", blake3::hash(input).to_hex());
    let path = dir.join(filename);
    if !path.exists() {
        fs::write(&path, input)?;
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::fuzz_write_into_corpus;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_corpus_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("leash-fuzzing-tests-{nanos}"))
    }

    #[test]
    fn writes_and_dedupes_by_content_hash() {
        let dir = temp_corpus_dir();
        // SAFETY: tests in this crate do not rely on this env var, and this test scopes
        // it to a temp unique directory.
        unsafe { std::env::set_var("LEASH_FUZZ_CORPUS_DIR", &dir) };

        let a = fuzz_write_into_corpus("escape_html", b"<script>alert(1)</script>")
            .expect("write corpus a");
        let b = fuzz_write_into_corpus("escape_html", b"<script>alert(1)</script>")
            .expect("write corpus b");

        assert_eq!(a, b);
        assert!(a.exists());
    }

    #[test]
    fn rejects_unsafe_target_name() {
        let result = fuzz_write_into_corpus("../escape_html", b"abc");
        assert!(result.is_err());
    }
}
