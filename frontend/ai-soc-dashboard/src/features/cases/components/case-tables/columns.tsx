'use client';

import Link from 'next/link';
import { Column, ColumnDef } from '@tanstack/react-table';
import { DataTableColumnHeader } from '@/components/ui/table/data-table-column-header';
import { Icons } from '@/components/icons';
import type { CaseFile } from '../../api/types';
import { SeverityBadge, StatusBadge } from '../case-badges';
import { CellAction } from './cell-action';
import { SEVERITY_OPTIONS, STATUS_OPTIONS } from './options';

function formatDate(value: string) {
  return new Intl.DateTimeFormat('en', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  }).format(new Date(value));
}

export const columns: ColumnDef<CaseFile>[] = [
  {
    id: 'case_id',
    accessorKey: 'case_id',
    header: ({ column }: { column: Column<CaseFile, unknown> }) => (
      <DataTableColumnHeader column={column} title='Case ID' />
    ),
    cell: ({ row }) => (
      <Link
        href={`/dashboard/cases/${row.original.case_id}`}
        className='font-medium underline-offset-4 hover:underline'
      >
        {row.original.case_id.slice(0, 12)}
      </Link>
    ),
    meta: {
      label: 'Case ID',
      placeholder: 'Search cases...',
      variant: 'text',
      icon: Icons.search
    },
    enableColumnFilter: true
  },
  {
    id: 'status',
    accessorKey: 'status',
    enableSorting: true,
    header: ({ column }: { column: Column<CaseFile, unknown> }) => (
      <DataTableColumnHeader column={column} title='Status' />
    ),
    cell: ({ row }) => <StatusBadge status={row.original.status} />,
    meta: {
      label: 'Status',
      variant: 'multiSelect',
      options: STATUS_OPTIONS
    },
    enableColumnFilter: true
  },
  {
    id: 'severity',
    accessorKey: 'severity',
    enableSorting: true,
    header: ({ column }: { column: Column<CaseFile, unknown> }) => (
      <DataTableColumnHeader column={column} title='Severity' />
    ),
    cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
    meta: {
      label: 'Severity',
      variant: 'multiSelect',
      options: SEVERITY_OPTIONS
    },
    enableColumnFilter: true
  },
  {
    id: 'category',
    accessorKey: 'category',
    header: ({ column }: { column: Column<CaseFile, unknown> }) => (
      <DataTableColumnHeader column={column} title='Category' />
    ),
    cell: ({ row }) => row.original.category ?? 'Pending triage'
  },
  {
    id: 'source',
    accessorKey: 'source',
    header: 'SOURCE',
    cell: ({ row }) => row.original.source ?? 'Wazuh'
  },
  {
    id: 'entities',
    header: ({ column }: { column: Column<CaseFile, unknown> }) => (
      <DataTableColumnHeader column={column} title='Entities' />
    ),
    cell: ({ row }) => row.original.entities.length
  },
  {
    id: 'evidence',
    header: ({ column }: { column: Column<CaseFile, unknown> }) => (
      <DataTableColumnHeader column={column} title='Evidence' />
    ),
    cell: ({ row }) => row.original.evidence.length
  },
  {
    id: 'updated_at',
    accessorKey: 'updated_at',
    header: ({ column }: { column: Column<CaseFile, unknown> }) => (
      <DataTableColumnHeader column={column} title='Updated' />
    ),
    cell: ({ row }) => formatDate(row.original.updated_at)
  },
  {
    id: 'actions',
    cell: ({ row }) => <CellAction data={row.original} />
  }
];
