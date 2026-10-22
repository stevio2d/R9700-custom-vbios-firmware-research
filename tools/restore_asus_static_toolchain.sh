#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tool_root="${repo_root}/.cache/asus-static-toolchain"
mkdir -p "${tool_root}/archives"

ghidra_archive="${tool_root}/archives/ghidra_12.1.4_PUBLIC_20260921.zip"
jdk_archive="${tool_root}/archives/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz"
ghidra_url="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip"
jdk_url="https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz"
ghidra_sha="ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
jdk_sha="ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94"
edk_commit="c1415771ac592ad8509351c46cd3cda4f38d7d52"

if [[ ! -f "${ghidra_archive}" ]]; then
  curl --fail --location --retry 3 "${ghidra_url}" --output "${ghidra_archive}"
fi
printf '%s  %s\n' "${ghidra_sha}" "${ghidra_archive}" | sha256sum --check --status
ghidra_stage="$(mktemp -d "${tool_root}/.ghidra-restore.XXXXXX")"
unzip -q "${ghidra_archive}" -d "${ghidra_stage}"
test -x "${ghidra_stage}/ghidra_12.1.4_PUBLIC/support/analyzeHeadless"
rm -rf "${tool_root}/ghidra"
mv "${ghidra_stage}" "${tool_root}/ghidra"

if [[ ! -f "${jdk_archive}" ]]; then
  curl --fail --location --retry 3 "${jdk_url}" --output "${jdk_archive}"
fi
printf '%s  %s\n' "${jdk_sha}" "${jdk_archive}" | sha256sum --check --status
jdk_stage="$(mktemp -d "${tool_root}/.jdk-restore.XXXXXX")"
tar -xzf "${jdk_archive}" --strip-components=1 -C "${jdk_stage}"
test -x "${jdk_stage}/bin/java"
rm -rf "${tool_root}/jdk21"
mv "${jdk_stage}" "${tool_root}/jdk21"

edk_source="${tool_root}/edk2"
if [[ ! -d "${edk_source}/.git" ]]; then
  git clone --filter=blob:none https://github.com/tianocore/edk2.git "${edk_source}"
fi
if [[ -n "$(git -C "${edk_source}" status --porcelain --untracked-files=no)" ]]; then
  printf 'Refusing to build from a modified EDK II source tree: %s\n' "${edk_source}" >&2
  exit 1
fi
git -C "${edk_source}" fetch --depth 1 origin "${edk_commit}"
git -C "${edk_source}" checkout --detach "${edk_commit}"
[[ "$(git -C "${edk_source}" rev-parse HEAD)" == "${edk_commit}" ]]
find "${edk_source}/BaseTools/Source/C/Common" -maxdepth 1 -type f \
  \( -name '*.o' -o -name '*.d' \) -delete
find "${edk_source}/BaseTools/Source/C/TianoCompress" -maxdepth 1 -type f \
  \( -name '*.o' -o -name '*.d' \) -delete
rm -f "${edk_source}/BaseTools/Source/C/libs/libCommon.a" \
  "${edk_source}/BaseTools/Source/C/bin/TianoCompress"
make -C "${edk_source}/BaseTools/Source/C/Common" -f GNUmakefile -j2
make -C "${edk_source}/BaseTools/Source/C/TianoCompress" -f GNUmakefile -j2

ghidra_root="${tool_root}/ghidra/ghidra_12.1.4_PUBLIC"
tianocompress="${edk_source}/BaseTools/Source/C/bin/TianoCompress"
"${tool_root}/jdk21/bin/java" -version
grep '^application.version=' "${ghidra_root}/Ghidra/application.properties"
test -x "${ghidra_root}/support/analyzeHeadless"
"${tianocompress}" --version
sha256sum "${ghidra_archive}" "${jdk_archive}" "${tianocompress}"
printf 'GHIDRA_ROOT=%s\nJDK_HOME=%s\nTIANOCOMPRESS=%s\n' "${ghidra_root}" "${tool_root}/jdk21" "${tianocompress}"
