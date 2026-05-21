'use client';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { DataTable } from '@/components/ui/table/data-table';
import { DataTableSkeleton } from '@/components/ui/table/data-table-skeleton';
import { DataTableToolbar } from '@/components/ui/table/data-table-toolbar';
import { Icons } from '@/components/icons';
import { getSortingStateParser } from '@/lib/parsers';
import { useDataTable } from '@/hooks/use-data-table';
import { useQuery } from '@tanstack/react-query';
import { parseAsInteger, parseAsString, useQueryStates } from 'nuqs';
import { casesQueryOptions } from '../../api/queries';
import { columns } from './columns';

const columnIds = columns.map((column) => column.id).filter(Boolean) as string[];

export function CasesTable() {
  const [params] = useQueryStates({
    page: parseAsInteger.withDefault(1),
    perPage: parseAsInteger.withDefault(10),
    case_id: parseAsString,
    status: parseAsString,
    severity: parseAsString,
    sort: getSortingStateParser(columnIds).withDefault([])
  });

  const filters = {
    page: params.page,
    limit: params.perPage,
    ...(params.case_id && { search: params.case_id }),
    ...(params.status && { status: params.status }),
    ...(params.severity && { severity: params.severity }),
    ...(params.sort.length > 0 && { sort: JSON.stringify(params.sort) })
  };

  const { data, isError, isLoading, error } = useQuery(casesQueryOptions(filters));
  const pageCount = Math.ceil((data?.total_cases ?? 0) / params.perPage);

  const { table } = useDataTable({
    data: data?.cases ?? [],
    columns,
    pageCount,
    shallow: true,
    debounceMs: 500,
    initialState: {
      columnPinning: { right: ['actions'] },
      sorting: [{ id: 'updated_at', desc: true }]
    }
  });

  if (isLoading) {
    return <DataTableSkeleton columnCount={columns.length} filterCount={3} />;
  }

  if (isError) {
    return (
      <Alert variant='destructive'>
        <Icons.alertCircle className='h-4 w-4' />
        <AlertTitle>Unable to load cases</AlertTitle>
        <AlertDescription>
          {error instanceof Error ? error.message : 'Check that the FastAPI backend is running.'}
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <DataTable table={table}>
      <DataTableToolbar table={table} />
    </DataTable>
  );
}
