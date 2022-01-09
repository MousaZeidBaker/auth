# Auth

## Develop
Activate virtual environment
```shell
poetry shell
```

Install dependencies
```shell
poetry install --remove-untracked
```

Install git hooks
```shell
pre-commit install --hook-type pre-commit
```

Run tests
```shell
pytest tests
```

Run linter
```shell
flake8 .
```

Format code
```shell
black .
```

Sort imports
```shell
isort .
```
