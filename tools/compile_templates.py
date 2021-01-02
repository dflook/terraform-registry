import sys

import jinja2

def compile_templates(source_path: str, dest_path: str):
    jinja_env = jinja2.Environment(
        auto_reload=False,
        loader=jinja2.FileSystemLoader(source_path),
        autoescape=jinja2.select_autoescape(['html', 'xml'])
    )

    jinja_env.compile_templates(dest_path, ignore_errors=False, log_function=lambda x: print(x))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage:\n\tcompile_templates.py <SOURCE_PATH> <DEST_PATH>')
    compile_templates(sys.argv[1], sys.argv[2])
