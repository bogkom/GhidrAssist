#!/usr/bin/env python3
"""Golden model of traversal rules, plus read-only production wiring contracts."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("fixture",ROOT/"tools/generate-synthetic-callgraph.py")
fixture=importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

def paths(start, depth):
    found=[]
    cycles=0
    cuts=0
    reachable=set()
    def visit(node, stack, calls):
        nonlocal cycles,cuts
        reachable.add(node)
        if node in (3,8,13,18):
            found.append((tuple(stack),tuple(calls),node))
        if node not in fixture.EDGES:
            return
        next_node=fixture.EDGES[node]
        if next_node in stack:
            cycles+=1
        elif len(calls)>=depth:
            cuts+=1
        else:
            visit(next_node,stack+[next_node],calls+[fixture.BASE+node*0x30])
    visit(start,[start],[])
    return found,reachable,cycles,cuts

class Traversal(unittest.TestCase):
    def test_reset_root_and_disconnected_writers(self):
        hits,reached,cycles,cuts=paths(0,8)
        self.assertEqual(reached,set(range(6)))
        self.assertEqual(cycles,1)
        self.assertEqual(cuts,0)
        self.assertEqual(len(hits),1)
        self.assertEqual(hits[0][0],(0,1,2,3))
        self.assertEqual(hits[0][1],(0x100,0x130,0x160))
        self.assertEqual(hits[0][2],3)

    def test_alternative_roots_depth_and_pagination(self):
        hits,reached,cycles,cuts=paths(6,20)
        self.assertEqual(reached,set(range(6,20)))
        self.assertEqual([h[2] for h in hits],[8,13,18])
        self.assertEqual([h[2] for h in hits[1:2]],[13])
        shallow,reachable,cycle,depth_cut=paths(0,2)
        self.assertEqual(shallow,[])
        self.assertEqual(reachable,{0,1,2})
        self.assertEqual(cycle,0)
        self.assertEqual(depth_cut,1)

    def test_production_readonly_wiring(self):
        java=(ROOT/"src/main/java/ghidrassist/automation/AutomationCallPaths.java").read_text()
        server=(ROOT/"src/main/java/ghidrassist/automation/AutomationServer.java").read_text()
        cli=(ROOT/"tools/ghidrassist-agent").read_text()
        self.assertIn('AutomationCallPaths.query(program',server)
        self.assertIn('"analysis.paths".equals(method)',server)
        self.assertIn('"paths": "analysis.paths"',cli)
        for token in ('isCall()', 'isWrite()', 'MAX_FUNCTIONS', 'MAX_STEPS',
                      'stack.contains(edge.target)', 'maxDepth>32',
                      'reachable_entries', 'unreachable_entries',
                      'write_site', 'call_sites', 'budget_exceeded'):
            self.assertIn(token,java)
        for mutation in ('startTransaction(', 'createFunction(', 'setBytes(', 'removeFunction('):
            self.assertNotIn(mutation,java)

if __name__=="__main__":
    unittest.main()
