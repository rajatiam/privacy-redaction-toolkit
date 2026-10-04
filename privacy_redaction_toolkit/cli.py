import argparse, json
from pathlib import Path
from .core import write_redacted, audit


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit and redact configured privacy exposures"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("audit")
    sub.add_argument("source")
    sub = commands.add_parser("redact")
    sub.add_argument("source")
    sub.add_argument("output")
    sub.add_argument("--salt-file")
    args = parser.parse_args(argv)
    result = (
        audit(json.loads(Path(args.source).read_text(encoding="utf-8")))
        if args.command == "audit"
        else write_redacted(args.source, args.output, args.salt_file)
    )
    print(json.dumps(result, indent=2))
