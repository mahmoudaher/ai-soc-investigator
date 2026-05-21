'use client';

import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger
} from '@/components/ui/dropdown-menu';
import { Icons } from '@/components/icons';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import type { CaseFile } from '../../api/types';

interface CellActionProps {
  data: CaseFile;
}

export function CellAction({ data }: CellActionProps) {
  const router = useRouter();

  return (
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button variant='ghost' className='h-8 w-8 p-0'>
          <span className='sr-only'>Open case actions</span>
          <Icons.ellipsis className='h-4 w-4' />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align='end'>
        <DropdownMenuLabel>Case actions</DropdownMenuLabel>
        <DropdownMenuItem onClick={() => router.push(`/dashboard/cases/${data.case_id}`)}>
          <Icons.arrowRight className='mr-2 h-4 w-4' /> Open case
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => {
            void navigator.clipboard.writeText(data.case_id);
            toast.success('Case ID copied');
          }}
        >
          <Icons.page className='mr-2 h-4 w-4' /> Copy case ID
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
