use core::fmt;

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
struct MessageError(String);

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MessageError {}

#[derive(Debug)]
struct ContextError {
    context: String,
    source: Error,
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.source)
    }
}

impl std::error::Error for ContextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.source)
    }
}

pub fn anyhow<M>(message: M) -> Error
where
    M: fmt::Display,
{
    Box::new(MessageError(message.to_string()))
}

pub trait Context<T> {
    fn context<C>(self, context: C) -> Result<T>
    where
        C: fmt::Display;

    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: fmt::Display,
        F: FnOnce() -> C;
}

impl<T, E> Context<T> for core::result::Result<T, E>
where
    E: Into<Error>,
{
    fn context<C>(self, context: C) -> Result<T>
    where
        C: fmt::Display,
    {
        self.map_err(|err| {
            Box::new(ContextError {
                context: context.to_string(),
                source: err.into(),
            }) as Error
        })
    }

    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: fmt::Display,
        F: FnOnce() -> C,
    {
        self.context(f())
    }
}

#[macro_export]
macro_rules! anyhow {
    ($msg:literal $(,)?) => {
        $crate::anyhow(format!($msg))
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::anyhow(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! bail {
    ($msg:literal $(,)?) => {
        return Err($crate::anyhow!($msg))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return Err($crate::anyhow(format!($fmt, $($arg)*)))
    };
}
