#!/bin/bash

# echo "### Rebuilding oCIS #####################################################"
rm ocis/bin/ocis
make -C ocis build

echo "### Running oCIS ########################################################"

# $ ./ocis/bin/ocis init
# =========================================
#  generated OCIS Config
# =========================================
#  configpath : /Users/mk/.ocis/config/ocis.yaml
#  user       : admin
#  password   : admin

# Load environment variables from files (default to ".env" if no files are provided)
ENV_FILES=("${@:-.env}")

for ENV_FILE in "${ENV_FILES[@]}"; do
    if [ -f "${ENV_FILE}" ]; then
        echo "Loading env file '${ENV_FILE}'..."
        set -a  # Automatically export all variables
        . "${ENV_FILE}"
        set +a
    else
        echo "Env file '${ENV_FILE}' not found, skipping..."
    fi
done

REVA_TRACING_ENABLED=true \
REVA_TRACING_ENDPOINT=localhost:6831 \
REVA_TRACING_COLLECTOR=http://localhost:14268/api/traces \
OCIS_TRACING_ENABLED=true \
OCIS_TRACING_ENDPOINT=localhost:6831 \
OCIS_TRACING_COLLECTOR=http://localhost:14268/api/traces \
    ./ocis/bin/ocis server
