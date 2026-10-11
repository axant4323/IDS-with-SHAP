#!/usr/bin/env python3
"""
X-NIDS Automated Project Checklist & Progress Tracker
Parses PROJECT_ROADMAP.md, tracks completion metrics across all 7 project phases,
displays an ASCII progress bar, and outputs immediate next tasks for project partners.
"""

import os
import re
import sys

ROADMAP_FILE = os.path.join(os.path.dirname(__file__), "PROJECT_ROADMAP.md")

def analyze_roadmap(filepath=ROADMAP_FILE):
    if not os.path.exists(filepath):
        print(f"[!] Error: {filepath} not found.")
        sys.exit(1)
        
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    phases = {}
    current_phase = "General"
    
    for line in lines:
        line_clean = line.strip()
        
        # Detect phase headers
        if line_clean.startswith("### Phase "):
            match = re.match(r"### (Phase \d+:[^(\n]+)", line_clean)
            if match:
                current_phase = match.group(1).strip()
                if current_phase not in phases:
                    phases[current_phase] = {"completed": 0, "pending": 0, "tasks": []}
                    
        # Detect checklist items
        if line_clean.startswith("- [x]") or line_clean.startswith("- [X]"):
            task_desc = line_clean[5:].strip()
            if current_phase not in phases:
                phases[current_phase] = {"completed": 0, "pending": 0, "tasks": []}
            phases[current_phase]["completed"] += 1
            phases[current_phase]["tasks"].append((True, task_desc))
            
        elif line_clean.startswith("- [ ]"):
            task_desc = line_clean[5:].strip()
            if current_phase not in phases:
                phases[current_phase] = {"completed": 0, "pending": 0, "tasks": []}
            phases[current_phase]["pending"] += 1
            phases[current_phase]["tasks"].append((False, task_desc))

    return phases

def render_dashboard(phases):
    total_completed = sum(p["completed"] for p in phases.values())
    total_pending = sum(p["pending"] for p in phases.values())
    total_tasks = total_completed + total_pending
    
    pct = (total_completed / max(1, total_tasks)) * 100.0
    
    bar_width = 30
    filled = int(round(bar_width * (total_completed / max(1, total_tasks))))
    bar = "█" * filled + "░" * (bar_width - filled)
    
    print("\n" + "=" * 76)
    print("      X-NIDS IMPLEMENTATION TRACKER & AUTO-CHECKLIST DASHBOARD      ")
    print("=" * 76)
    print(f"Overall Completion: [{bar}] {pct:.1f}%")
    print(f"Metrics Summary   : {total_completed} Completed Tasks | {total_pending} Pending Tasks | {total_tasks} Total Tasks")
    print("-" * 76)
    print(f"{'Phase / Module':<50} {'Progress':<12} {'Status':<10}")
    print("-" * 76)
    
    for phase_name, data in phases.items():
        comp = data["completed"]
        pend = data["pending"]
        tot = comp + pend
        phase_pct = (comp / max(1, tot)) * 100.0
        
        if comp == tot and tot > 0:
            status_str = "✅ DONE"
        elif comp > 0:
            status_str = "🔄 ACTIVE"
        else:
            status_str = "🚀 READY"
            
        progress_str = f"{comp}/{tot} ({phase_pct:4.0f}%)"
        print(f"{phase_name:<50} {progress_str:<12} {status_str:<10}")
        
    print("=" * 76)
    
    # Highlight top pending tasks for partners
    print("\n🎯 IMMEDIATE TASKS READY FOR PARTNERS TO IMPLEMENT:")
    print("-" * 76)
    pending_shown = 0
    for phase_name, data in phases.items():
        for is_done, desc in data["tasks"]:
            if not is_done:
                # Strip markdown bolding for clean CLI output
                clean_desc = desc.replace("**", "")
                phase_tag = phase_name.split(":")[0].strip()
                print(f"  [>] [{phase_tag}] {clean_desc}")
                pending_shown += 1
                if pending_shown >= 5:
                    break
        if pending_shown >= 5:
            break
            
    print("-" * 76)
    print("💡 To mark a task as done: Change `- [ ]` to `- [x]` in PROJECT_ROADMAP.md")
    print("   Then re-run: python check_progress.py\n")

if __name__ == "__main__":
    phases_data = analyze_roadmap()
    render_dashboard(phases_data)
