#! /usr/bin/env python3

"""
Mr.Roboto: Malware Analysis Scripts
usage main.py -e dropbox/ -o saved_specimens/ -vt <vt-api-keys>
"""
import sys

from scripts import Analysis, Banner, Extractor

import argparse

module_name = "Mr.Roboto: Malware Analysis Scripts"
__version__ = "0.0.1"


class RobotoInvoker(object):
    def __init__(self):
        self.commands = []

    def add_command(self, command):
        self.commands.append(command)

    def run(self):
        for command in self.commands:
            command.execute()


if __name__ == "__main__":
    invoker = RobotoInvoker()
    msg1 = "Malware analysis scripts"
    parser = argparse.ArgumentParser(prog='Mr.Roboto: ', description=msg1)
    # parser.add_argument("-p", "--peAnalysis", type=str, required=False, help="Set sample to analyze")
    parser.add_argument("-f", "--samples_path", required=False, type=str, help="Set file directory of samples")
    parser.add_argument("-o", "--output_path", type=str, required=False, help="Set output directory of samples")
    parser.add_argument("--unzip", action='store_true', help="Unzip samples to output path")
    parser.add_argument("-vt", "--vt_api", type=str, help="Virus total API keys")

    args = parser.parse_args()
    invoker.add_command(Banner.WelcomeMessage())

    if args.samples_path is None:
        parser.print_help(sys.stderr)
        print("\nPlease specify path directory of the samples")
        sys.exit(1)

    # Unzip Routine
    if args.unzip is not None:
        invoker.add_command(Extractor.ProcessSamples(args.samples_path, args.output_path))
    # Perform triage
    if args.samples_path is not None:
        invoker.add_command(Analysis.StaticAnalysis(args.output_path))
        if args.vt_api is not None:
            invoker.add_command(Analysis.Osint(args.vt_api))

    # PE static analysis
    # elif args.peAnalysis is not None:
    #    invoker.add_command(Analysis.PeStaticAnalysis(args.file, args.outputPath))
    # Perform Osint Query DB
    # elif args.vt_api is not None:
    # invoker.add_command(Analysis.Osint(args.vt_api))

    invoker.run()