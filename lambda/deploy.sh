#!/usr/bin/env bash
# Despliega la bóveda en una Lambda desde ESTE checkout, sin esperar a una release.
# Quien despliega una release no necesita esto: sube la plantilla de la release en la consola
# de CloudFormation (ver README.md).
#
#   lambda/deploy.sh <nombre> [--concurrency N] [--proxy wss://…]
#
# Pide la contraseña del administrador la primera vez (no se queda en ningún archivo). Las
# credenciales y la región salen del entorno, normalmente de la bóveda:
#   dotrino-env run --ns aws-<cuenta> -- env AWS_REGION=us-east-1 lambda/deploy.sh <nombre>
#
# El zip se sube a un bucket de trabajo (`dotrino-vault-dev-<cuenta>-<región>`) y la pila lo
# baja de ahí por una URL firmada de una hora, igual que bajaría el de una release.
set -euo pipefail
NAME=${1:?usage: lambda/deploy.sh <name> [--concurrency N] [--proxy URL]}; shift
CONCURRENCY=0; PROXY=wss://proxy.dotrino.com
while [ $# -gt 0 ]; do
  case "$1" in
    --concurrency) CONCURRENCY=$2; shift 2 ;;
    --proxy) PROXY=$2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
: "${AWS_REGION:?set AWS_REGION}"
export AWS_DEFAULT_REGION=$AWS_REGION AWS_PAGER=""
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
V=$(node -p "require('$REPO/package.json').version")
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
DEV=dotrino-vault-dev-$ACCOUNT-$AWS_REGION
STACK=dotrino-vault-$NAME

aws s3api head-bucket --bucket "$DEV" 2>/dev/null || aws s3 mb "s3://$DEV" >/dev/null
bash "$HERE/build.sh" "placeholder" >/dev/null
ZIP="$REPO/dist/dotrino-vault-lambda-$V.zip"
SHA=$(sha256sum "$ZIP" | cut -d' ' -f1)
aws s3 cp "$ZIP" "s3://$DEV/dotrino-vault-lambda-$SHA.zip" >/dev/null
URL=$(aws s3 presign "s3://$DEV/dotrino-vault-lambda-$SHA.zip" --expires-in 3600)

PASS=()
if ! aws cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1; then
  read -r -s -p "admin password for the new vault (12+ chars): " PW; echo
  PASS=(AdminPassword="$PW")
else
  PASS=(AdminPassword=UsePreviousValue)
fi
TPL=$(mktemp); sed -e "s#__VERSION__#$V-dev#" "$HERE/template.yaml" > "$TPL"
# `UsePreviousValue` no se puede pasar por --parameter-overrides con valor: se omite el
# parámetro y CloudFormation conserva el anterior.
[ "${PASS[0]}" = "AdminPassword=UsePreviousValue" ] && PASS=()
aws cloudformation deploy --stack-name "$STACK" --template-file "$TPL" --capabilities CAPABILITY_IAM \
  --parameter-overrides Name="$NAME" ProxyUrl="$PROXY" ReservedConcurrency="$CONCURRENCY" CodeUrl="$URL" CodeSha256="$SHA" "${PASS[@]}" \
  --no-fail-on-empty-changeset
rm -f "$TPL"
aws cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output text
