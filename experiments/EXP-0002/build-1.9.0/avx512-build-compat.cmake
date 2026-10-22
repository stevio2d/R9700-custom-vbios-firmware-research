# Upstream v1.9.0 uses _pdep_u64 in AVX level 3 without enabling BMI2.
# Scope the missing compiler feature to this unused-on-EPYC7532 ISA tier.
cmake_language(DEFER CALL target_compile_options avx_lvl3 PRIVATE -mbmi2)
