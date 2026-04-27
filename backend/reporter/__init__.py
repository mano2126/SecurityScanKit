from .pdf_report import generate as _pdf_gen
from .excel_report import generate as _excel_gen

class PDFReporter:
    async def generate(self, job_id, target, results):
        return await _pdf_gen(job_id, target, results)

class ExcelReporter:
    async def generate(self, job_id, target, results):
        return await _excel_gen(job_id, target, results)
