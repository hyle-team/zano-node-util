{
  "targets": [
    {
      "target_name": "cryptonote",
      "sources": [
        "src/main.cc",
        "src/currency_core/currency_format_utils.cpp",
        "src/currency_core/currency_format_utils_blocks.cpp",
        "src/crypto/tree-hash.c",
        "src/crypto/crypto.cpp",
        "src/crypto/crypto-ops.c",
        "src/crypto/crypto-ops-data.c",
        "src/crypto/hash.c",
        "src/crypto/keccak.c",
        "src/crypto/wild_keccak.cpp",
        "src/common/base58.cpp"
      ],
      "include_dirs": [
        "src",
        "src/contrib/epee/include",
        "src/contrib/eos_portable_archive",
        "src/contrib",
        "<!(node -e \"require('nan')\")"
      ],
      "link_settings": {
        "libraries": [
          "-lboost_system",
          "-lboost_date_time"
        ]
      },
      "cflags_cc!": [
        "-fno-exceptions",
        "-fno-rtti"
      ],
      "cflags_cc": [
        "-std=c++0x",
        "-fexceptions",
        "-frtti"
      ],
      "conditions": [
        [
          "OS=='mac'",
          {
            "xcode_settings": {
              "GCC_ENABLE_CPP_RTTI": "YES",
              "GCC_ENABLE_CPP_EXCEPTIONS": "YES"
            }
          }
        ]
      ]
    }
  ]
}