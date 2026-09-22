// Generated from data/seeds, data/synth and data/processed by counting the real files.
// Every number on the Architecture data-pipeline section comes from here.

export const DATA_PIPELINE = {
  "seedTotal": 250,
  "seedClasses": 10,
  "publicRows": 3296,
  "publicSources": {
    "mcptox": 1338,
    "jackhhao": 1289,
    "deepset": 662,
    "mcpsecbench": 7
  },
  "generatedRows": 730,
  "generatedClasses": 7,
  "pngCount": 80,
  "wavCount": 40,
  "llmRows": 130,
  "llmClasses": 10,
  "splits": {
    "train_real": 2642,
    "val": 327,
    "test": 327
  }
} as const
