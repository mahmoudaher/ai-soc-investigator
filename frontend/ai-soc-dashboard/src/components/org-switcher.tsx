'use client';

import { Icons } from '@/components/icons';
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem, useSidebar } from '@/components/ui/sidebar';
import { useRouter } from 'next/navigation';

export function OrgSwitcher() {
  const { state } = useSidebar();
  const router = useRouter();

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <SidebarMenuButton
          size='lg'
          onClick={() => router.push('/dashboard/overview')}
          className='data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground'
        >
          <div className='bg-sidebar-primary text-sidebar-primary-foreground flex aspect-square size-8 shrink-0 items-center justify-center overflow-hidden rounded-lg'>
            <Icons.warning className='size-4' />
          </div>
          <div
            className={`grid flex-1 text-left text-sm leading-tight transition-all duration-200 ease-in-out ${
              state === 'collapsed'
                ? 'invisible max-w-0 overflow-hidden opacity-0'
                : 'visible max-w-full opacity-100'
            }`}
          >
            <span className='truncate font-medium'>AI SOC Investigator</span>
            <span className='text-muted-foreground truncate text-xs'>Case workspace</span>
          </div>
        </SidebarMenuButton>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
