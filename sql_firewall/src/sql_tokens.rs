//! SQL tokens for the keyword and built-in injection checks (README 6.6).
//!
//! Both checks look at the statement's SQL tokens, as PostgreSQL's lexer
//! reads them (fingerprints::policy_readings), not at its raw text: a word
//! inside a string literal, a dollar-quoted string, a comment (nested or
//! not), or a quoted identifier's quotes is not SQL. Regex rules keep
//! matching the raw statement text, because patterns are written for it
//! (the installation default looks for `--` comments).
//!
//! When a backslash gives the statement two readings, a check that matches
//! either reading matches. When the lexer accepts no reading the caller uses
//! the raw text, which finds at least as much.

#[derive(Debug, PartialEq, Eq)]
pub enum Token {
    /// A keyword, lower case.
    Keyword(String),
    /// An identifier's name, after PostgreSQL's case folding and quoting.
    Ident(String),
    /// A literal's value: the string contents, or the number as written.
    Literal(String),
    /// An operator, punctuation, or parameter.
    Other(String),
}

/// Splits the token text produced by the policy scan. Tokens are separated
/// by single spaces; spaces occur inside a token only within quotes, where a
/// quote is doubled.
pub fn parse(text: &str) -> Vec<Token> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ' ' {
            i += 1;
            continue;
        }
        // Optional prefix of a quoted token: U& (identifier or string), B, X.
        let (prefix_len, quote) = match (chars[i], chars.get(i + 1), chars.get(i + 2)) {
            ('"', _, _) => (0, Some('"')),
            ('\'', _, _) => (0, Some('\'')),
            ('U', Some('&'), Some(q)) if *q == '"' || *q == '\'' => (2, Some(*q)),
            ('B' | 'X', Some('\''), _) => (1, Some('\'')),
            _ => (0, None),
        };
        if let Some(q) = quote {
            let mut j = i + prefix_len + 1;
            let mut value = String::new();
            while j < chars.len() {
                if chars[j] == q {
                    if chars.get(j + 1) == Some(&q) {
                        value.push(q);
                        j += 2;
                        continue;
                    }
                    j += 1;
                    break;
                }
                value.push(chars[j]);
                j += 1;
            }
            tokens.push(if q == '"' { Token::Ident(value) } else { Token::Literal(value) });
            i = j;
            continue;
        }
        let mut j = i;
        while j < chars.len() && chars[j] != ' ' {
            j += 1;
        }
        let word: String = chars[i..j].iter().collect();
        let first = word.chars().next().unwrap_or(' ');
        tokens.push(if first.is_ascii_digit() || (first == '.' && word.len() > 1 && word != "..") {
            Token::Literal(word)
        } else if first.is_ascii_uppercase() || first == '_' {
            Token::Keyword(word.to_ascii_lowercase())
        } else {
            Token::Other(word)
        });
        i = j;
    }
    tokens
}

fn token_word(token: &Token) -> Option<&str> {
    match token {
        Token::Keyword(word) | Token::Ident(word) => Some(word.as_str()),
        _ => None,
    }
}

/// The first configured keyword (one or more words, matched as consecutive
/// keywords or identifiers, case-insensitively) that occurs in `tokens`.
pub fn keyword_hit(tokens: &[Token], keywords: &[String]) -> Option<String> {
    for keyword in keywords {
        let words: Vec<String> = keyword.split_whitespace().map(str::to_ascii_lowercase).collect();
        if words.is_empty() || words.len() > tokens.len() {
            continue;
        }
        let hit = tokens.windows(words.len()).any(|window| {
            window
                .iter()
                .zip(&words)
                .all(|(token, word)| token_word(token).is_some_and(|t| t.eq_ignore_ascii_case(word)))
        });
        if hit {
            return Some(keyword.clone());
        }
    }
    None
}

/// A tautology in SQL: `OR` followed by a literal, `=`, and the same literal
/// value (`OR 1=1`, `OR '1'='1'`). `WHERE 1=1` and `AND 1=1` narrow nothing
/// and are common in generated SQL, so they do not count.
pub fn tautology(tokens: &[Token]) -> bool {
    tokens.windows(4).any(|w| {
        matches!(&w[0], Token::Keyword(k) if k == "or")
            && matches!(&w[2], Token::Other(op) if op == "=")
            && matches!((&w[1], &w[3]), (Token::Literal(a), Token::Literal(b)) if a == b)
    })
}

thread_local! {
    static LAST: std::cell::RefCell<Option<(String, Option<Vec<Vec<Token>>>)>> = const { std::cell::RefCell::new(None) };
}

/// The token readings of `query`, scanned once per statement text: the
/// keyword and built-in checks of one inspection share them.
pub fn readings(query: &str) -> Option<Vec<Vec<Token>>> {
    let cached = LAST.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|(text, _)| text == query)
            .map(|(_, readings)| readings.as_ref().map(|r| r.iter().map(|t| t.iter().map(clone_token).collect()).collect()))
    });
    if let Some(found) = cached {
        return found;
    }
    let scanned = crate::fingerprints::policy_readings(query)
        .map(|texts| texts.iter().map(|text| parse(text)).collect::<Vec<_>>());
    let copy = scanned.as_ref().map(|r| r.iter().map(|t| t.iter().map(clone_token).collect()).collect());
    LAST.with(|slot| *slot.borrow_mut() = Some((query.to_string(), copy)));
    scanned
}

fn clone_token(token: &Token) -> Token {
    match token {
        Token::Keyword(s) => Token::Keyword(s.clone()),
        Token::Ident(s) => Token::Ident(s.clone()),
        Token::Literal(s) => Token::Literal(s.clone()),
        Token::Other(s) => Token::Other(s.clone()),
    }
}
