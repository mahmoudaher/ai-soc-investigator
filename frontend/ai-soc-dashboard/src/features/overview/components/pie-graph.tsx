'use client';

import { LabelList, Pie, PieChart } from 'recharts';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent
} from '@/components/ui/chart';
import { Badge } from '@/components/ui/badge';
import { Icons } from '@/components/icons';
import { useQuery } from '@tanstack/react-query';
import { caseSummaryQueryOptions } from '@/features/cases/api/queries';
import { buildSeverityMix } from '../utils/case-aggregations';
import { PieGraphSkeleton } from './pie-graph-skeleton';

const chartConfig = {
  cases: {
    label: 'Cases'
  },
  critical: {
    label: 'Critical',
    color: 'var(--chart-1)'
  },
  high: {
    label: 'High',
    color: 'var(--chart-2)'
  },
  medium: {
    label: 'Medium',
    color: 'var(--chart-3)'
  },
  low: {
    label: 'Low',
    color: 'var(--chart-4)'
  },
  unknown: {
    label: 'Unknown',
    color: 'var(--chart-5)'
  }
} satisfies ChartConfig;

export function PieGraph() {
  const { data, isError, isLoading } = useQuery(caseSummaryQueryOptions());
  const chartData = buildSeverityMix(data ?? []).map((item) => ({
    ...item,
    fill: `var(--color-${item.severity})`
  }));

  if (isLoading) {
    return <PieGraphSkeleton />;
  }

  if (isError) {
    return (
      <Card className='flex h-full flex-col'>
        <CardHeader className='items-center pb-0'>
          <CardTitle>Severity Mix</CardTitle>
          <CardDescription>Unable to load severity distribution</CardDescription>
        </CardHeader>
        <CardContent className='text-muted-foreground text-sm'>
          Check that the FastAPI backend is running.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className='flex h-full flex-col'>
      <CardHeader className='items-center pb-0'>
        <CardTitle>
          Severity Mix
          <Badge variant='outline'>
            <Icons.warning />
            Risk
          </Badge>
        </CardTitle>
        <CardDescription>Case distribution after triage classification</CardDescription>
      </CardHeader>
      <CardContent className='flex flex-1 items-center justify-center pb-0'>
        <ChartContainer
          config={chartConfig}
          className='[&_.recharts-text]:fill-background mx-auto aspect-square max-h-[300px] min-h-[250px]'
        >
          <PieChart>
            <ChartTooltip content={<ChartTooltipContent nameKey='cases' hideLabel />} />
            <Pie
              data={chartData}
              innerRadius={30}
              dataKey='cases'
              nameKey='severity'
              radius={10}
              cornerRadius={8}
              paddingAngle={4}
            >
              <LabelList
                dataKey='cases'
                stroke='none'
                fontSize={12}
                fontWeight={500}
                fill='currentColor'
                formatter={(value: number) => value.toString()}
              />
            </Pie>
          </PieChart>
        </ChartContainer>
      </CardContent>
    </Card>
  );
}
