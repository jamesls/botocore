all:
	rm -rf dist
	pyinstaller --additional-hooks-dir hooks/ scripts/make-request && (cd dist/make-request/ && ./make-request)
