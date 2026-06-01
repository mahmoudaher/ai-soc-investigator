'use client';

import { Area, AreaChart, CartesianGrid, XAxis } from 'recharts';

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
import { buildThroughputSeries } from '../utils/case-aggregations';
import { AreaGraphSkeleton } from './area-graph-skeleton';

const chartConfig = {
  open: {
    label: 'Open',
    color: 'var(--chart-1)'
  },
  closed: {
    label: 'Closed',
    color: 'var(--chart-2)'
  }
} satisfies ChartConfig;

export function AreaGraph() {
  const { data, isError, isLoading } = useQuery(caseSummaryQueryOptions());
  const chartData = buildThroughputSeries(data ?? []);

  if (isLoading) {
    return <AreaGraphSkeleton />;
  }

  if (isError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Investigation Throughput</CardTitle>
          <CardDescription>Unable to load live throughput data</CardDescription>
        </CardHeader>
        <CardContent className='text-muted-foreground text-sm'>
          Check that the FastAPI backend is running.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Investigation Throughput
          <Badge variant='outline'>
            <Icons.trendingUp />
            Stabilizing
          </Badge>
        </CardTitle>
        <CardDescription>Open versus completed investigations over time</CardDescription>
      </CardHeader>
      <CardContent>
        <ChartContainer config={chartConfig}>
          <AreaChart accessibilityLayer data={chartData}>
            <CartesianGrid vertical={false} strokeDasharray='3 3' />
            <XAxis
              dataKey='month'
              tickLine={false}
              axisLine={false}
              tickMargin={8}
              tickFormatter={(value) => value.slice(0, 3)}
            />
            <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
            <defs>
              <DottedBackgroundPattern config={chartConfig} />
            </defs>
            <Area
              dataKey='closed'
              type='natural'
              fill='url(#dotted-background-pattern-closed)'
              fillOpacity={0.4}
              stroke='var(--color-closed)'
              stackId='a'
              strokeWidth={0.8}
            />
            <Area
              dataKey='open'
              type='natural'
              fill='url(#dotted-background-pattern-open)'
              fillOpacity={0.4}
              stroke='var(--color-open)'
              stackId='a'
              strokeWidth={0.8}
            />
          </AreaChart>
        </ChartContainer>
      </CardContent>
    </Card>
  );
}

const DottedBackgroundPattern = ({ config }: { config: ChartConfig }) => {
  const items = Object.fromEntries(
    Object.entries(config).map(([key, value]) => [key, value.color])
  );

  return (
    <>
      {Object.entries(items).map(([key, value]) => (
        <pattern
          key={key}
          id={`dotted-background-pattern-${key}`}
          x='0'
          y='0'
          width='7'
          height='7'
          patternUnits='userSpaceOnUse'
        >
          <circle cx='5' cy='5' r='1.5' fill={value} opacity={0.5}></circle>
        </pattern>
      ))}
    </>
  );
};
