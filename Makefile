.PHONY: all commit clean

all: commit

commit:
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo ">>> Обнаружены изменения, делаю коммит..."; \
		git add .; \
		if [ -z "$1" ]; then \
			git commit --allow-empty-message -m ""; \
		else \
			git commit -m "$1"; \
		fi; \
		git push; \
	else \
		echo ">>> Нет изменений для коммита."; \
	fi

clean:
	git clean -fd
