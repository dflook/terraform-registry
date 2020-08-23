all: build/lambda.zip build/registry.template

BRANCH:=$(shell git rev-parse --abbrev-ref HEAD)
TAG:=$(shell git describe --always --dirty=+WIP-${USER}-$(shell date "+%Y-%m-%dT%H:%M:%S%z"))

LAMBDA_CODE=$(shell find src/)

build/venv: requirements-dev.txt
	python3 -m venv --clear --copies $@
	build/venv/bin/pip install -r $<

build/lambda_requirements: src/requirements.txt build/venv
	rm -rf $@
	build/venv/bin/pip install -r $< --target $@

build/lambda.zip: build/lambda_requirements $(LAMBDA_CODE)
	rm $@
	cd build/lambda_requirements && zip --recurse-paths $(abspath $@) *
	cd src && zip $(abspath $@) *.py

build/registry.template: create_template.py build/lambda.zip build/venv
	TROPO_REAL_BOOL=true build/venv/bin/python $< "$(TAG)" --output $@

clean:
	rm -rf build

publish: build/lambda.zip build/registry.template
	aws s3 cp build/lambda.zip s3://terraform-registry-build/${TAG}/lambda.zip
	aws s3 cp build/registry.template s3://terraform-registry-build/${TAG}/registry.template

deploy: build/lambda.zip build/registry.template
	aws s3 cp build/lambda.zip s3://terraform-registry-build/${TAG}/lambda.zip
	aws cloudformation deploy --template-file build/registry.template --stack-name Dan --s3-bucket terraform-registry-build --force-upload --s3-prefix "${TAG}" --capabilities CAPABILITY_NAMED_IAM

.PHONY: all clean publish build/registry.template
