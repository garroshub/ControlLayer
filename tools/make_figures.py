"""Regenerate evidence figures from public per-episode metadata."""
import csv
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT=Path(__file__).resolve().parents[1]
DATA=json.loads((ROOT/'evidence/final.json').read_text(encoding='utf8'))
S=DATA['summary']
OUT=ROOT/'assets'
OUT.mkdir(exist_ok=True)
BLUE='#38608c'
GREEN='#187b68'
RED='#b34741'
GRAY='#74808c'
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':11,'axes.spines.top':False,
    'axes.spines.right':False,'axes.edgecolor':'#bec6cd','axes.labelcolor':'#27313b',
    'text.color':'#27313b','xtick.color':'#56616d','ytick.color':'#56616d',
    'figure.facecolor':'white','axes.facecolor':'white','savefig.facecolor':'white',
    'svg.hashsalt':'control-layer-v0'})


def save(fig,name):
    for extension in ('svg','png','pdf'):
        fig.savefig(OUT/(name+'.'+extension),dpi=220,bbox_inches='tight')
    plt.close(fig)


def utility():
    fig,axes=plt.subplots(1,2,figsize=(11,4.2),gridspec_kw={'width_ratios':[1.15,1]})
    ax=axes[0]
    values=[S['official_normal_successes'][a] for a in ('rules','v0')]
    bars=ax.barh(['R2 rules','Control Layer V0'],values,color=[BLUE,GREEN],height=.52)
    ax.set_xlim(0,97);ax.set_xticks([0,25,50,75,97]);ax.set_xlabel('Official task completions / 97')
    ax.invert_yaxis();ax.grid(axis='x',alpha=.16);ax.set_axisbelow(True)
    for bar,value in zip(bars,values):
        ax.text(value+1.3,bar.get_y()+bar.get_height()/2,f'{value}/97',va='center',fontweight='bold')
    ax.set_title('Same actor, tasks and tool catalog',loc='left',fontweight='bold',pad=17)
    ax=axes[1]
    counts=[3,0,24,70]
    labels=['Gained semantic success','Lost semantic success','Equal after review','Exactly equal behavior']
    bars=ax.barh(labels,counts,color=[GREEN,RED,GRAY,'#d2d8dd'],height=.52)
    ax.invert_yaxis();ax.set_xlim(0,97);ax.set_xlabel('Paired tasks / 97');ax.grid(axis='x',alpha=.16);ax.set_axisbelow(True)
    for bar,value in zip(bars,counts):ax.text(value+1.2,bar.get_y()+bar.get_height()/2,str(value),va='center')
    ax.set_title('Net semantic gain +3 tasks',loc='left',fontweight='bold',pad=17)
    fig.suptitle('Paired task completion',x=.04,ha='left',fontsize=19,fontweight='bold')
    fig.text(.04,-.02,'Descriptive benchmark result. Exact paired McNemar p = 0.25 (3 gains, 0 losses).\nReused development benchmark. Equal behavior establishes zero paired difference.',fontsize=9,color=GRAY)
    fig.tight_layout(rect=[0,.07,1,.90]);save(fig,'paired-utility')


def security():
    fig,axes=plt.subplots(1,2,figsize=(10,4.3))
    for ax,title,values,limit in ((axes[0],'Official proposal-trace scoring',[0,1],2),
                                 (axes[1],'Audited unauthorized native writes',[0,0],2)):
        bars=ax.bar(['R2 rules','V0'],values,color=[BLUE,GREEN],width=.48)
        ax.set_ylim(0,limit);ax.set_yticks([0,1,2]);ax.set_ylabel('Observed episodes / 54 per arm')
        ax.set_title(title,loc='left',fontweight='bold',fontsize=12,pad=16)
        ax.grid(axis='y',alpha=.16);ax.set_axisbelow(True)
        for bar,value in zip(bars,values):ax.text(bar.get_x()+bar.get_width()/2,value+.07,f'{value}/54',ha='center',fontweight='bold')
    fig.suptitle('Official attack scores and executed writes',x=.06,ha='left',fontsize=19,fontweight='bold')
    fig.text(.06,-.01,'The one official success counts denied proposals. Actual calls are webpage/channel reads only.\n108 attack captures audited. Fixed episodes span 27 scenarios across two styles. Coverage is limited to these mechanisms.',fontsize=9,color=GRAY)
    fig.tight_layout(rect=[0,.07,1,.90]);save(fig,'security-evidence')


def cost():
    fig,ax=plt.subplots(figsize=(10,4))
    modes=['clean','attack']
    xs=[0,1]
    for offset,arm,color,label in ((-.18,'rules',BLUE,'R2 rules'),(.18,'v0',GREEN,'Control Layer V0')):
        vals=[S['warm_cost_by_scope'][mode][arm] for mode in modes]
        bars=ax.bar([x+offset for x in xs],vals,width=.32,color=color,label=label)
        for bar,value in zip(bars,vals):ax.text(bar.get_x()+bar.get_width()/2,value+35,f'{value:,.0f} s',ha='center',fontsize=10)
    ax.set_xticks(xs,['97 normal tasks','54 fixed attacks']);ax.set_ylim(0,2600)
    ax.set_ylabel('Matched warm wall time, seconds');ax.grid(axis='y',alpha=.16);ax.set_axisbelow(True)
    ax.legend(frameon=False,loc='upper right')
    ax.set_title('Measured runtime cost',loc='left',fontsize=19,fontweight='bold',pad=23)
    fig.text(.13,.94,f"Overall cost increased by {100*S['warm_cost_increase_fraction']:.2f}%",color=RED,fontsize=12)
    fig.text(.13,-.01,'151 matched pairs. Includes per-episode process and observer overhead.\nThis run shows higher execution cost.',fontsize=9,color=GRAY)
    fig.tight_layout(rect=[0,.07,1,.94]);save(fig,'runtime-cost')


def source_table():
    rows=[['official_normal_rules',44,97],['official_normal_v0',47,97],['paired_semantic_gains',3,97],
          ['paired_semantic_losses',0,97],['official_attack_rules',0,54],['official_attack_v0',1,54],
          ['audited_attack_writes_rules',0,54],['audited_attack_writes_v0',0,54],
          ['new_exposed_negative_v0',8,8],['new_unauthorized_effect_v0',0,8],
          ['warm_wall_rules_seconds',S['warm_seconds']['rules'],151],['warm_wall_v0_seconds',S['warm_seconds']['v0'],151]]
    with (ROOT/'evidence/figure-data.csv').open('w',newline='',encoding='utf8') as stream:
        writer=csv.writer(stream);writer.writerow(['metric','value','denominator_or_pairs']);writer.writerows(rows)


if __name__=='__main__':
    utility();security();cost();source_table()
