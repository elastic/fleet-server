// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import "encoding/hex"

// LabelFromHash derives a human-readable "adjective-noun" label from the first
// two bytes of a hex-encoded SHA-256 hash. The mapping is deterministic and
// stable: the wordlists are fixed in source so the same hash always produces
// the same label across deployments and library versions.
// Returns "" for empty or malformed input.
func LabelFromHash(hexHash string) string {
	if len(hexHash) < 4 {
		return ""
	}
	b, err := hex.DecodeString(hexHash[:4])
	if err != nil || len(b) < 2 {
		return ""
	}
	return labelAdjectives[b[0]] + "-" + labelNouns[b[1]]
}

// labelAdjectives is a fixed 256-entry wordlist. Index = byte value of hash[0].
var labelAdjectives = [256]string{ //nolint:dupl // parallel wordlists are intentionally similar in structure
	"able", "agile", "alert", "amber", "ample", "arctic", "arid", "atomic", // 0–7
	"azure", "balmy", "beige", "binary", "bold", "brave", "bright", "brisk", // 8–15
	"broad", "bronze", "brown", "bulky", "calm", "candid", "chilly", "clean", // 16–23
	"clear", "clever", "coarse", "cold", "cool", "coral", "crisp", "crimson", // 24–31
	"curvy", "cushy", "cyan", "cyclic", "damp", "dark", "deep", "dense", // 32–39
	"deft", "dewy", "digital", "dim", "downy", "dry", "dull", "dynamic", // 40–47
	"eager", "earthy", "edgy", "elastic", "epic", "even", "exact", "faint", // 48–55
	"fancy", "fast", "feisty", "fine", "firm", "flat", "fluid", "foggy", // 56–63
	"formal", "free", "fresh", "frosty", "fuzzy", "gentle", "glad", "gold", // 64–71
	"grand", "great", "green", "grey", "hardy", "harsh", "hasty", "hazy", // 72–79
	"heavy", "hollow", "honest", "hot", "huge", "humid", "hybrid", "icy", // 80–87
	"idle", "indigo", "inert", "ivory", "jade", "jolly", "jumpy", "keen", // 88–95
	"khaki", "kind", "large", "latent", "light", "lime", "linear", "lively", // 96–103
	"local", "lone", "loose", "lost", "low", "loyal", "lucky", "lumpy", // 104–111
	"lush", "maroon", "mellow", "merry", "micro", "mild", "misty", "modal", // 112–119
	"moist", "mossy", "muddy", "murky", "musty", "muted", "mystic", "naive", // 120–127
	"narrow", "navy", "nimble", "noble", "null", "obscure", "odd", "olive", // 128–135
	"optic", "orange", "oval", "pale", "patchy", "pink", "plain", "plum", // 136–143
	"plump", "polar", "prime", "proud", "pure", "purple", "quantum", "quiet", // 144–151
	"radial", "rainy", "rapid", "rare", "raw", "rich", "rigid", "rocky", // 152–159
	"round", "rough", "ruby", "rugged", "rust", "sage", "sandy", "scalar", // 160–167
	"sharp", "shady", "silver", "silky", "slim", "slow", "small", "smooth", // 168–175
	"snowy", "soft", "solar", "solid", "sonic", "starry", "static", "stout", // 176–183
	"stormy", "strong", "sunny", "swift", "tame", "teal", "thick", "thin", // 184–191
	"tidal", "tiny", "tropical", "true", "vast", "violet", "virtual", "vivid", // 192–199
	"warm", "wavy", "white", "wide", "wild", "windy", "wintry", "wise", // 200–207
	"young", "zippy", "zonal", "blunt", "breezy", "bumpy", "burly", "chunky", // 208–215
	"classy", "cobalt", "comfy", "cozy", "crunchy", "dusty", "fizzy", "flaky", // 216–223
	"fluffy", "giddy", "glossy", "gritty", "groovy", "handy", "jaunty", "jazzy", // 224–231
	"lofty", "loopy", "manic", "moody", "nervy", "nutty", "perky", "plucky", // 232–239
	"quirky", "salty", "savvy", "scaly", "soggy", "spiky", "speedy", "steely", // 240–247
	"stuffy", "tangy", "tardy", "thorny", "trashy", "trendy", "tricky", "twisty", // 248–255
}

// labelNouns is a fixed 256-entry wordlist. Index = byte value of hash[1].
var labelNouns = [256]string{ //nolint:dupl // parallel wordlists are intentionally similar in structure
	"ant", "ape", "arc", "arch", "asp", "auk", "bank", "bat", // 0–7
	"bay", "beam", "bear", "bee", "bird", "bit", "boar", "bolt", // 8–15
	"bond", "brook", "buck", "bull", "cache", "cat", "cave", "chip", // 16–23
	"cliff", "cloud", "coast", "cod", "code", "core", "cow", "crag", // 24–31
	"creek", "crest", "crow", "crypt", "curl", "dale", "data", "deer", // 32–39
	"dell", "dew", "disk", "dog", "dove", "duck", "dune", "dust", // 40–47
	"edge", "eel", "elk", "ewe", "feed", "fern", "file", "fish", // 48–55
	"fjord", "flag", "floe", "flow", "flux", "foam", "ford", "fork", // 56–63
	"fox", "frog", "frost", "gale", "gate", "gear", "glade", "glen", // 64–71
	"gnu", "gorge", "grid", "grove", "gulf", "gust", "hash", "hawk", // 72–79
	"heap", "heath", "hen", "hill", "hog", "hook", "hub", "ibis", // 80–87
	"isle", "jay", "kelp", "key", "kite", "knoll", "knot", "lake", // 88–95
	"lamb", "lark", "lea", "leaf", "ledge", "link", "lion", "loch", // 96–103
	"lock", "log", "loop", "lynx", "map", "marsh", "mask", "mesa", // 104–111
	"mesh", "mist", "mode", "mole", "moor", "moss", "moth", "mule", // 112–119
	"mud", "newt", "node", "oak", "ore", "owl", "ox", "pack", // 120–127
	"page", "path", "peak", "peat", "peer", "pike", "pine", "pipe", // 128–135
	"plain", "plug", "pod", "pond", "pool", "port", "probe", "pulse", // 136–143
	"queue", "ram", "rat", "ray", "reef", "ridge", "rill", "ring", // 144–151
	"rock", "rook", "root", "rune", "rush", "sand", "sap", "seal", // 152–159
	"shard", "shell", "shoal", "shrew", "shrub", "sink", "slope", "slot", // 160–167
	"slug", "snail", "snake", "snow", "soil", "spark", "spring", "spur", // 168–175
	"stack", "stem", "stone", "storm", "strand", "stump", "swan", "swamp", // 176–183
	"sync", "tag", "tap", "tide", "toad", "token", "trace", "tree", // 184–191
	"trunk", "tube", "tune", "type", "unit", "vale", "verb", "vole", // 192–199
	"wasp", "wave", "wire", "wolf", "wren", "yak", "zone", "bloom", // 200–207
	"bough", "brine", "bud", "burr", "bush", "cairn", "cap", "chalk", // 208–215
	"char", "cob", "colt", "cord", "cove", "cub", "cup", "dam", // 216–223
	"den", "dome", "drift", "drop", "drum", "dusk", "fin", "flint", // 224–231
	"frond", "helm", "hemp", "herb", "husk", "iris", "kern", "loft", // 232–239
	"loom", "lore", "lure", "mast", "moat", "molt", "monk", "pore", // 240–247
	"reed", "rind", "rime", "rump", "runt", "silt", "skew", "spore", // 248–255
}
