test:
	python -m pytest tests/ -s

lint:
	python -m pylint lightdsa/ --fail-under=10