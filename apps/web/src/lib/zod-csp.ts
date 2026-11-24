import {z} from "zod";

// Strict script-src policies report Zod's caught JIT probe as an eval violation.
z.config({jitless: true});
