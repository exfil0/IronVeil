# Advanced Usage

## Extending Passive Sources
To add a new passive source (e.g., Shodan):
1. In phases/passive.py, add a function like `passive_shodan(self)`.
2. Call it in phase_passive_recon in enumerator.py.
3. Add API key handling in config.py.

## Custom Permutations
Modify common_parts in phases/active.py.

## Integration
Use as library: `from ironveil.enumerator import SubdomainEnumerator; enum = SubdomainEnumerator(...); enum.run()`.
