import logging
from pathlib import Path
import subprocess
from subprocess import CalledProcessError
import sys

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

clang = Path("C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\Llvm\\x64\\bin\\clang-cl.exe")
if not clang.is_file():
    logging.fatal("Cannot find clang executable")
    exit(1)

lib = Path("C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.30.30705\\bin\\Hostx64\\x64\\lib.exe")
if not lib.is_file():
    logging.fatal("Cannot find lib executable")
    exit(1)

def run_build(args):
    try:
        subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except CalledProcessError as ex:
        sys.stderr.buffer.write(ex.stdout)
        logging.fatal("Build terminated due to previous errors")
        exit(1)

capstone_include_dir = Path("D:\\Codespace\\capstone\\build\\install\\include")

source_dir = Path("D:\\Codespace\\libxdc\\src")
source_files = list(source_dir.glob("*.c"))
object_files = list(map(lambda f: f.name + ".obj", source_files))

for (f, of) in zip(source_files, object_files):
    logging.info("Building %s", of)
    run_build([
        str(clang),
        "-c",
        "-Ofast",
        "-finline-functions",
        "-I", str(capstone_include_dir),
        "/MD",
        # "/DDEBUG_TRACES",
        "-o", str(of),
        str(f),
    ])

logging.info("Build completed")
logging.info("Archiving")

link_args = [
    str(lib),
    "/OUT:libxdc.lib",
]
link_args += list(map(str, object_files))
run_build(link_args)

logging.info("Object archive created")
