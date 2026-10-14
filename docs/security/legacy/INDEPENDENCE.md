# NARF independence boundary

NARF is a standalone project.

It does not require, import, invoke, discover, configure, or depend on any external governance system, project harness, workspace variable, private repository, or parent checkout in order to run or test.

The reference implementation and its tests are self-contained in this repository and use the Python standard library.

External systems may integrate NARF as a consumer, but that relationship is one-way: an integration may depend on NARF; NARF does not depend on the integrating system.

The canonical standalone verification commands are:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```
