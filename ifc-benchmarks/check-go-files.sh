#!/usr/bin/env bash

expect_go_version=1.26

# this doesn't overwrite files (use gofmt -w for that), but it exits if wrong
gofmt -d . || exit 1

for suite in ./*; do
	[ -d "$suite" ] || continue

	echo "========== $suite =========="
	cd "$suite"

	expect_mod_number=1

	for module in ./*; do
		[ -d "$module" ] || continue

		echo "--- $module ---"
		cd "$module"

		mod_number=$(basename "$module" | cut -d'-' -f1)

		if [[ "$mod_number" != x* ]]; then
			# remove leading zeros (so number is not interpreted as base 8)
			mod_number=$((10#$mod_number))

			if [ ! "$mod_number" -eq "$expect_mod_number" ]; then
				echo "ERROR: Module number \`$mod_number\` not crescent"
				exit 1
			fi

			expect_mod_number=$(("$mod_number"+1))
		fi

		if [ ! -f "go.mod" ]; then
			echo "ERROR: No go.mod file found"
			exit 1
		fi

		mod_name_path=$(basename "$module" | cut -d'-' -f2-)
		mod_name_declared=$(grep '^module' go.mod | cut -d' ' -f2)

		if [ "$mod_name_path" != "$mod_name_declared" ]; then
			echo "ERROR: Declared name \`$mod_name_declared\` does not match!"
			exit 1
		fi

		go_version_declared=$(grep '^go' go.mod | cut -d' ' -f2)

		if [ "$go_version_declared" != "$expect_go_version" ]; then
			left="Go version \`$expect_go_version\`"
			right="\`$go_version_declared\` declaration"
			echo "ERROR: Expected $left, but found $right"
			exit 1
		fi

		if [ -f "main.go" ]; then
			pkg_name=$(grep 'package ' main.go | cut -d' ' -f2)

			if [ "$pkg_name" != "main" ]; then
				echo "Expected main package in main.go, but found \`$pkg_name\`"
				exit 1
			fi
		fi

		golangci-lint run --tests=false

		cd ..
	done

	cd ..
	echo
done
