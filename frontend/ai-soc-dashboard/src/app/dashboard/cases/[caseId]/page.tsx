import PageContainer from '@/components/layout/page-container';
import CaseDetailView from '@/features/cases/components/case-detail-view';

export const metadata = {
  title: 'AI SOC Investigator: Case Detail'
};

type PageProps = { params: Promise<{ caseId: string }> };

export default async function Page(props: PageProps) {
  const params = await props.params;

  return (
    <PageContainer
      pageTitle='Case File'
      pageDescription='Evidence, entities, timeline, ATT&CK mapping, recommendations, and workflow checkpoints.'
    >
      <CaseDetailView caseId={params.caseId} />
    </PageContainer>
  );
}
