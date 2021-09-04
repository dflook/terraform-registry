all: build/lambda.zip build/terraform.template

BRANCH:=$(shell git rev-parse --abbrev-ref HEAD)
TAG:=$(shell git describe --always --dirty=+WIP-${USER}-$(shell date "+%Y-%m-%dT%H:%M:%S%z"))

REGISTRY_CODE:=$(shell find src/ -name "*.py")
STATIC_ASSETS:=$(shell find assets/)

build/venv: requirements-dev.txt src/requirements.txt
	python3 -m venv --clear --copies $@
	build/venv/bin/pip install -r $<

build/lambda_requirements: src/requirements.txt | build/venv
	rm -rf $@
	build/venv/bin/pip install -r $< --target $@

build/requirements.zip: build/lambda_requirements
	rm -f "$@"
	cd build/lambda_requirements && zip --recurse-paths $(abspath $@) *

build/templates.zip: $(wildcard templates/*) tools/compile_templates.py | build/venv
	build/venv/bin/python tools/compile_templates.py templates $@

build/lambda.zip: build/requirements.zip build/templates.zip $(REGISTRY_CODE) $(STATIC_ASSETS)
	cp $< $@
	cd src && zip $(abspath $@) $(REGISTRY_CODE:src/%=%)
	cd build && zip $(abspath $@) templates.zip
	cd assets && zip $(abspath $@) $(STATIC_ASSETS:assets/%=%)

build/terraform.template: $(wildcard cloudformation/*.py) build/lambda.zip | build/venv
	TROPO_REAL_BOOL=true build/venv/bin/python cloudformation/template.py "$(TAG)" --output $@
	cfn-lint $@ || true

publish: build/lambda.zip build/terraform.template
	aws s3 cp build/terraform.template s3://dflook-terraform-registry/build/cloudformation-template/$$(sha256sum build/terraform.template | cut -d ' ' -f 1).template
	aws s3 cp build/lambda.zip s3://dflook-terraform-registry/build/lambda-package/$$(sha256sum build/lambda.zip | cut -d ' ' -f 1).zip

deploy: build/terraform.template build/lambda.zip | publish
	aws --region eu-west-1 cloudformation update-stack --stack-name TerraformRegistry --template-body file://$< --capabilities CAPABILITY_NAMED_IAM --parameters ParameterKey=DomainName,ParameterValue=terraform-dev.flook.org ParameterKey=HostedZone,ParameterValue=Z2KZ5YTUFZNC7G ParameterKey=GitHubClientId,ParameterValue=7809679faec6b806d706 ParameterKey=GitHubClientSecret,ParameterValue=6fafa01322d657aa8db5ab0d777795a930029295 ParameterKey=AdminEmail,ParameterValue=daniel@flook.org
	aws --region eu-west-1 cloudformation wait stack-update-complete --stack-name TerraformRegistry

clean:
	rm -rf build

test:
	mypy src --disallow-subclassing-any --disallow-untyped-defs --disallow-incomplete-defs --check-untyped-defs --disallow-untyped-decorator --warn-redundant-casts --warn-unused-ignores --warn-return-any --no-implicit-reexport --strict-equality --ignore-missing-imports
	mypy cloudformation --disallow-subclassing-any --disallow-untyped-defs --disallow-incomplete-defs --check-untyped-defs --disallow-untyped-decorator --warn-redundant-casts --warn-unused-ignores --warn-return-any --no-implicit-reexport --strict-equality --ignore-missing-imports

.DELETE_ON_ERROR:
.PHONY: all clean publish deploy test
