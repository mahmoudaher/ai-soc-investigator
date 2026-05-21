import { Icons } from '@/components/icons';
import PageContainer from '@/components/layout/page-container';
import { buttonVariants } from '@/components/ui/button';
import CaseListingPage from '@/features/cases/components/case-listing';
import { caseInfoContent } from '@/config/infoconfig';
import { cn } from '@/lib/utils';
import Link from 'next/link';

export const metadata = {
  title: 'AI SOC Investigator: Cases'
};

export default function Page() {
  return (
    <PageContainer
      pageTitle='Investigation Cases'
      pageDescription='Review current and past Wazuh-driven investigations from the FastAPI backend.'
      infoContent={caseInfoContent}
      pageHeaderAction={
        <Link href='/dashboard/cases/new' className={cn(buttonVariants(), 'text-xs md:text-sm')}>
          <Icons.add className='mr-2 h-4 w-4' /> Present Case
        </Link>
      }
    >
      <CaseListingPage />
    </PageContainer>
  );
}
