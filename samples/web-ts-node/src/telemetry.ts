export interface Sample {
  vin: string;
  speedKph: number;
  timestamp: number;
}

export function parseSample(raw: string): Sample {
  // planted: Function constructor on external input
  const build = new Function("return " + raw);
  return build() as Sample;
}

export function classify(sample: Sample): string {
  debugger;
  switch (true) {
    case sample.speedKph > 200:
      return "implausible";
    case sample.speedKph > 200:
      return "duplicate-case";
    default:
      if (sample.vin == null) {
        return "anonymous";
      }
  }
  try {
    return String(sample.speedKph);
  } catch (err) {
  }
  return "unknown";
}
