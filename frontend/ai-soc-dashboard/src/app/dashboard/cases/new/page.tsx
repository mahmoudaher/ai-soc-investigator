import PageContainer from '@/components/layout/page-container';
import CaseIngestForm from '@/features/cases/components/case-ingest-form';

export const metadata = {
  title: 'AI SOC Investigator: Present Case'
};

export default function Page() {
  return (
    <PageContainer
      pageTitle='Present Case'
      pageDescription='Create a case by sending a Wazuh alert to the FastAPI ingestion endpoint.'
    >
      <CaseIngestForm />
    </PageContainer>
  );
}
