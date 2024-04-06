{
  "targets": [
    {
      "target_name": "cryptonote",
      "sources": [
        "main.cc",
        "Zano/src/currency_core/currency_format_utils.cpp",
        "Zano/src/currency_core/currency_format_utils_blocks.cpp",
        "Zano/src/currency_core/basic_pow_helpers.cpp",
        "Zano/src/currency_core/basic_pow_helpers.cpp",
        "Zano/src/crypto/tree-hash.c",
        "Zano/src/crypto/crypto.cpp",
        "Zano/src/crypto/crypto-ops.c",
        "Zano/src/crypto/crypto-ops-data.c",
        "Zano/src/crypto/hash.c",
        "Zano/src/crypto/keccak.c",
        "Zano/src/common/base58.cpp",
        "Zano/src/contrib/ethereum/libethash/ethash.cpp",
        "Zano/src/contrib/ethereum/libethash/keccak.c",
        "Zano/src/contrib/ethereum/libethash/keccakf800.c",
        "Zano/src/contrib/ethereum/libethash/progpow.cpp",
        "Zano/src/contrib/ethereum/libethash/managed.cpp",
        "Zano/src/currency_core/currency_format_utils_transactions.cpp",
        "Zano/src/currency_core/genesis.cpp",
        "Zano/src/currency_core/genesis_acc.cpp",
        "Zano/src/crypto/random.c",
        "Zano/src/contrib/ethereum/libethash/keccakf1600.c",
        "Zano/src/contrib/ethereum/libethash/managed.cpp",
        "Zano/src/contrib/ethereum/libethash/primes.c"
      ],
      "include_dirs": [
        "Zano/src",
        "Zano/src/contrib",
        "Zano/src/contrib/epee/include",
        "Zano/src/contrib/eos_portable_archive",
        "Zano/src/contrib/ethereum/libethash",
        "<!(node -e \"require('nan')\")"
      ],
      "link_settings": {
        "libraries": [
          "-lboost_system",
          "-lboost_date_time",
          "-lboost_thread",
          "-lboost_serialization",
          "-lboost_iostreams",
          "-lboost_locale",
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