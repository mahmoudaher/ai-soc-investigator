import { create } from 'zustand';
import { v4 as uuid } from 'uuid';
// import { persist } from 'zustand/middleware';

export type Priority = 'low' | 'medium' | 'high';

export type Task = {
  id: string;
  title: string;
  priority: Priority;
  description?: string;
  assignee?: string;
  dueDate?: string;
};

type KanbanState = {
  columns: Record<string, Task[]>;
  setColumns: (columns: Record<string, Task[]>) => void;
  addTask: (title: string, description?: string) => void;
};

const initialColumns: Record<string, Task[]> = {
  backlog: [
    {
      id: '1',
      title: 'Normalize Wazuh authentication alert',
      priority: 'high',
      assignee: 'ingest',
      dueDate: '2026-05-20'
    },
    {
      id: '2',
      title: 'Extract host, user, IP, and process entities',
      priority: 'medium',
      assignee: 'triage_agent',
      dueDate: '2026-05-20'
    },
    {
      id: '3',
      title: 'Prepare analyst-facing case summary',
      priority: 'low',
      assignee: 'reporter_agent',
      dueDate: '2026-05-21'
    },
    {
      id: '9',
      title: 'Validate normalized CaseFile schema',
      priority: 'medium',
      assignee: 'casefile',
      dueDate: '2026-05-21'
    }
  ],
  inProgress: [
    {
      id: '4',
      title: 'Run recon enrichment on extracted observables',
      priority: 'high',
      assignee: 'recon_agent',
      dueDate: '2026-05-20'
    },
    {
      id: '5',
      title: 'Collect evidence and timeline events',
      priority: 'medium',
      assignee: 'evidence_agent',
      dueDate: '2026-05-20'
    },
    {
      id: '10',
      title: 'Persist workflow checkpoints',
      priority: 'high',
      assignee: 'checkpointing',
      dueDate: '2026-05-20'
    }
  ],
  done: [
    {
      id: '6',
      title: 'Map suspicious behavior to MITRE techniques',
      priority: 'high',
      assignee: 'mapper_agent',
      dueDate: '2026-05-19'
    },
    {
      id: '7',
      title: 'Generate response recommendations',
      priority: 'medium',
      assignee: 'finalizer_agent',
      dueDate: '2026-05-19'
    },
    {
      id: '8',
      title: 'Render case detail page for presentation',
      priority: 'low',
      assignee: 'frontend',
      dueDate: '2026-05-19'
    }
  ]
};

export const useTaskStore = create<KanbanState>()(
  // To enable persistence across refreshes, uncomment the persist wrapper below:
  // persist(
  (set) => ({
    columns: initialColumns,

    setColumns: (columns) => set({ columns }),

    addTask: (title, description) =>
      set((state) => ({
        columns: {
          ...state.columns,
          backlog: [
            {
              id: uuid(),
              title,
              description,
              priority: 'medium' as Priority,
              assignee: undefined,
              dueDate: undefined
            },
            ...(state.columns.backlog ?? [])
          ]
        }
      }))
  })
  //   ,
  //   { name: 'kanban-store' }
  // )
);
