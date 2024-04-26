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
        "Zano/src/crypto/crypto-sugar.cpp",
        "Zano/src/crypto/zarcanum.cpp",
        "Zano/src/crypto/range_proofs.cpp",
        "Zano/src/crypto/crypto-ops-data.c",
        "Zano/src/crypto/hash.c",
        "Zano/src/crypto/keccak.c",
        "Zano/src/common/base58.cpp",
        "Zano/contrib/ethereum/libethash/ethash.cpp",
        "Zano/contrib/ethereum/libethash/keccak.c",
        "Zano/contrib/ethereum/libethash/keccakf800.c",
        "Zano/contrib/ethereum/libethash/progpow.cpp",
        "Zano/contrib/ethereum/libethash/managed.cpp",
        "Zano/src/currency_core/currency_format_utils_transactions.cpp",
        "Zano/src/currency_core/genesis.cpp",
        "Zano/src/currency_core/genesis_acc.cpp",
        "Zano/src/crypto/random.c",
        "Zano/contrib/ethereum/libethash/keccakf1600.c",
        "Zano/contrib/ethereum/libethash/managed.cpp",
        "Zano/contrib/ethereum/libethash/primes.c"
      ],
      "include_dirs": [
        "Zano/src/crypto",
        "Zano/src",
        "Zano/contrib",
        "Zano/contrib/epee/include",
        "Zano/contrib/eos_portable_archive",
        "Zano/contrib/ethereum/libethash",
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
        "-std=c++17",
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

