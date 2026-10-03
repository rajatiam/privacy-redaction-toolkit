import argparse, json
from .core import write_redacted


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Redact configured sensitive keys and recognizable text patterns"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("redact")
    run.add_argument("source")
    run.add_argument("output")
    run.add_argument("--salt-file")
    args = parser.parse_args(argv)
    print(
        json.dumps(write_redacted(args.source, args.output, args.salt_file), indent=2)
    )
