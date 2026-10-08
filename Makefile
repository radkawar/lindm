.PHONY: bootstrap lint fmt audit test-tooling

bootstrap:
	npm ci --ignore-scripts
	npm run hooks:install

lint:
	npm run check

fmt:
	npm run format

audit:
	npm run audit:dependencies

test-tooling:
	npm run test:tooling
