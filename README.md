# windows_IR

Windows 시스템에서 디지털 포렌식 / 침해사고 대응을 위한 아티팩트 수집 자동화 스크립트입니다.  
이벤트 로그, 프로세스 정보, 네트워크 연결, 서비스/드라이버 등 주요 정보를 수집하여 CSV 형태로 저장합니다.

## Usage
```powershell
.\windows_IR.ps1 --Help
.\windows_IR.ps1 -CaseId "<ID>" -Days <N> -OutputPath "<PATH>"
