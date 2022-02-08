##############
# Dependencies
#
ARG PYTHON_VER=3.8
FROM python:${PYTHON_VER} AS base

WORKDIR /usr/src/app

# Install poetry for dep management
RUN pip install poetry
RUN poetry config virtualenvs.create false

# Install project manifest
COPY pyproject.toml .

# Install production dependencies
RUN poetry install --no-dev

############
# Unit tests
#
FROM base AS test

# Install full dependencies
RUN poetry install

# Copy in the application code
COPY . .

############
# Linting
#
# Runs all necessary linting and code checks
RUN echo 'Running Flake8' && \
    flake8 . && \
    # echo 'Running Black' && \
    # black --check --diff . && \
    # echo 'Running Pylint' && \
    # find . -name '*.py' | xargs pylint  && \
    echo 'Running Yamllint' && \
    yamllint . && \
    # echo 'Running pydocstyle' && \
    # pydocstyle . && \
    echo 'Running Bandit' && \
    bandit --recursive ./ --configfile .bandit.yml

# Run full test suite including integration
ENTRYPOINT ["pytest"]

# Default to running colorful, verbose pytests
CMD ["--color=yes", "-vvv"]

#############
# Final image
#
# This creates a runnable CLI container
FROM python:3.8-slim AS cli

WORKDIR /usr/src/app

COPY --from=base /usr/src/app /usr/src/app
COPY --from=base /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
COPY --from=base /usr/local/bin /usr/local/bin

COPY ./ofd_global_nat .

ENTRYPOINT ["python"]
