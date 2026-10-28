"""stub.py <NNNN> <file.rs> [--tests-only]: fn bodies outside `mod tests`
become todo!("rfc NNNN"); every #[test] / #[tokio::test] gets
#[ignore = "rfc NNNN"]. Fix by hand afterwards: const fns (use panic!),
fns returning impl Trait (delete private ones), unused params and fields."""
import re
import sys

RFC = f'rfc {sys.argv[1]}'
IGNORE = f'#[ignore = "{RFC}"]'


def skip_str(s, i):
    """i at a quote or r#; returns index after the literal."""
    if s[i] == 'r':
        j = i + 1
        hashes = 0
        while s[j] == '#':
            hashes += 1
            j += 1
        assert s[j] == '"'
        end = '"' + '#' * hashes
        return s.index(end, j + 1) + len(end)
    j = i + 1
    while s[j] != '"':
        j += 2 if s[j] == '\\' else 1
    return j + 1


def scan(s, i, stop):
    """From i, skip strings, chars, comments; return index of first char in
    `stop` at bracket depth 0 (parens and brackets)."""
    depth = 0
    while i < len(s):
        c = s[i]
        if s.startswith('//', i):
            i = s.index('\n', i)
            continue
        if c == '"' or (c == 'r' and re.match(r'r#*"', s[i:]) and not s[i - 1].isalnum()):
            i = skip_str(s, i)
            continue
        if c == "'":
            m = re.match(r"'(\\.|[^\\'])'", s[i:]) or re.match(r"'\\u\{[0-9a-f]+\}'", s[i:])
            if m:
                i += m.end()
                continue
        if c in '([':
            depth += 1
        elif c in ')]':
            depth -= 1
        elif depth == 0 and c in stop:
            return i
        i += 1
    raise ValueError('unbalanced')


def body_end(s, i):
    """i at '{'; index of the matching '}'."""
    depth = 0
    while True:
        j = scan(s, i, '{}')
        depth += 1 if s[j] == '{' else -1
        if depth == 0:
            return j
        i = j + 1


FN = re.compile(r'^([ \t]*)(pub(\([a-z]+\))? )?(async )?(const )?(unsafe )?fn \w+', re.M)


def stub(s):
    tests = re.search(r'^#\[cfg\(test\)\]\nmod tests \{', s, re.M)
    limit = tests.start() if tests else len(s)
    out, pos = [], 0
    for m in FN.finditer(s):
        if m.start() < pos or m.start() >= limit:
            continue
        j = scan(s, m.end(), '{;')
        if s[j] == ';':
            continue
        end = body_end(s, j)
        ind = m.group(1)
        out.append(s[pos:j + 1])
        out.append(f'\n{ind}    todo!("{RFC}")\n{ind}')
        pos = end
    out.append(s[pos:])
    s = ''.join(out)
    lines = s.split('\n')
    i = 0
    while i < len(lines) and (lines[i].startswith('//!') or lines[i].startswith('#![')):
        i += 1
    lines.insert(i, '#![allow(unused_variables, unused_imports, dead_code)]')
    return '\n'.join(lines)


def ignore(s):
    return re.sub(r'^([ \t]*)(#\[(tokio::)?test(\(.*\))?\])\n',
                  lambda m: f'{m.group(1)}{m.group(2)}\n{m.group(1)}{IGNORE}\n', s, flags=re.M)


path = sys.argv[2]
s = open(path).read()
if '--tests-only' not in sys.argv:
    s = stub(s)
open(path, 'w').write(ignore(s))
