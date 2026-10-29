<?xml version="1.0" encoding="UTF-8"?>
<!-- DEMO SCL for the sniffer demo capture: MU01_QW1G matches the stream MU01_QW1G_01 (CT 300/1, VT 110 kV/100 V),
     MU02_QW1G has confRev 2 (the stream has 1) -> no secondary values, the reason is shown -->
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B">
  <Header id="demo_mu"/>
  <Communication><SubNetwork name="PB_A" type="8-MMS">
      <ConnectedAP iedName="MU01_QW1G" apName="AP1"><SMV ldInst="MU01" cbName="MU01_QW1G_01"><Address>
        <P type="MAC-Address">01-0C-CD-04-01-11</P><P type="APPID">4011</P><P type="VLAN-ID">01B</P><P type="VLAN-PRIORITY">4</P>
      </Address></SMV></ConnectedAP>
      <ConnectedAP iedName="MU02_QW1G" apName="AP1"><SMV ldInst="MU01" cbName="MU02_QW1G_01"><Address>
        <P type="MAC-Address">01-0C-CD-04-01-13</P><P type="APPID">4013</P><P type="VLAN-ID">01D</P><P type="VLAN-PRIORITY">4</P>
      </Address></SMV></ConnectedAP>
  </SubNetwork></Communication>
  <IED name="MU01_QW1G" manufacturer="DEMO" type="MU">
    <AccessPoint name="AP1"><Server><Authentication/>
      <LDevice inst="MU01">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
          <DataSet name="PhsMeas1">
          <FCDA ldInst="MU01" prefix="I01A" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01A" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01B" lnClass="TCTR" lnInst="2" doName="AmpSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01B" lnClass="TCTR" lnInst="2" doName="AmpSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01C" lnClass="TCTR" lnInst="3" doName="AmpSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01C" lnClass="TCTR" lnInst="3" doName="AmpSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01N" lnClass="TCTR" lnInst="4" doName="AmpSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01N" lnClass="TCTR" lnInst="4" doName="AmpSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01A" lnClass="TVTR" lnInst="1" doName="VolSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01A" lnClass="TVTR" lnInst="1" doName="VolSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01B" lnClass="TVTR" lnInst="2" doName="VolSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01B" lnClass="TVTR" lnInst="2" doName="VolSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01C" lnClass="TVTR" lnInst="3" doName="VolSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01C" lnClass="TVTR" lnInst="3" doName="VolSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01N" lnClass="TVTR" lnInst="4" doName="VolSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01N" lnClass="TVTR" lnInst="4" doName="VolSv" daName="q" fc="MX"/>
          </DataSet>
          <SampledValueControl name="MU01_QW1G_01" datSet="PhsMeas1" confRev="1" smvID="MU01_QW1G_01" multicast="true" smpRate="80" nofASDU="1"/>
        </LN0>
        <LN prefix="I01A" lnClass="TCTR" inst="1" lnType="TCTR_T">
          <DOI name="ARtg"><SDI name="setMag"><DAI name="i"><Val>1</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>300.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="I01B" lnClass="TCTR" inst="2" lnType="TCTR_T">
          <DOI name="ARtg"><SDI name="setMag"><DAI name="i"><Val>1</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>300.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="I01C" lnClass="TCTR" inst="3" lnType="TCTR_T">
          <DOI name="ARtg"><SDI name="setMag"><DAI name="i"><Val>1</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>300.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="I01N" lnClass="TCTR" inst="4" lnType="TCTR_T">
          <DOI name="ARtg"><SDI name="setMag"><DAI name="i"><Val>1</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>300.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="U01A" lnClass="TVTR" inst="1" lnType="TVTR_T">
          <DOI name="VRtg"><SDI name="setMag"><DAI name="i"><Val>100</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>1100.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="U01B" lnClass="TVTR" inst="2" lnType="TVTR_T">
          <DOI name="VRtg"><SDI name="setMag"><DAI name="i"><Val>100</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>1100.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="U01C" lnClass="TVTR" inst="3" lnType="TVTR_T">
          <DOI name="VRtg"><SDI name="setMag"><DAI name="i"><Val>100</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>1100.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="U01N" lnClass="TVTR" inst="4" lnType="TVTR_T">
          <DOI name="VRtg"><SDI name="setMag"><DAI name="i"><Val>100</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>1100.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
      </LDevice>
    </Server></AccessPoint>
  </IED>
  <IED name="MU02_QW1G" manufacturer="DEMO" type="MU">
    <AccessPoint name="AP1"><Server><Authentication/>
      <LDevice inst="MU01">
        <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
          <DataSet name="PhsMeas1">
          <FCDA ldInst="MU01" prefix="I01A" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01A" lnClass="TCTR" lnInst="1" doName="AmpSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01B" lnClass="TCTR" lnInst="2" doName="AmpSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01B" lnClass="TCTR" lnInst="2" doName="AmpSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01C" lnClass="TCTR" lnInst="3" doName="AmpSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01C" lnClass="TCTR" lnInst="3" doName="AmpSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01N" lnClass="TCTR" lnInst="4" doName="AmpSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="I01N" lnClass="TCTR" lnInst="4" doName="AmpSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01A" lnClass="TVTR" lnInst="1" doName="VolSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01A" lnClass="TVTR" lnInst="1" doName="VolSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01B" lnClass="TVTR" lnInst="2" doName="VolSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01B" lnClass="TVTR" lnInst="2" doName="VolSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01C" lnClass="TVTR" lnInst="3" doName="VolSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01C" lnClass="TVTR" lnInst="3" doName="VolSv" daName="q" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01N" lnClass="TVTR" lnInst="4" doName="VolSv" daName="instMag.i" fc="MX"/>
          <FCDA ldInst="MU01" prefix="U01N" lnClass="TVTR" lnInst="4" doName="VolSv" daName="q" fc="MX"/>
          </DataSet>
          <SampledValueControl name="MU02_QW1G_01" datSet="PhsMeas1" confRev="2" smvID="MU02_QW1G_01" multicast="true" smpRate="80" nofASDU="1"/>
        </LN0>
        <LN prefix="I01A" lnClass="TCTR" inst="1" lnType="TCTR_T">
          <DOI name="ARtg"><SDI name="setMag"><DAI name="i"><Val>1</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>300.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="I01B" lnClass="TCTR" inst="2" lnType="TCTR_T">
          <DOI name="ARtg"><SDI name="setMag"><DAI name="i"><Val>1</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>300.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="I01C" lnClass="TCTR" inst="3" lnType="TCTR_T">
          <DOI name="ARtg"><SDI name="setMag"><DAI name="i"><Val>1</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>300.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="I01N" lnClass="TCTR" inst="4" lnType="TCTR_T">
          <DOI name="ARtg"><SDI name="setMag"><DAI name="i"><Val>1</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>300.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="U01A" lnClass="TVTR" inst="1" lnType="TVTR_T">
          <DOI name="VRtg"><SDI name="setMag"><DAI name="i"><Val>100</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>1100.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="U01B" lnClass="TVTR" inst="2" lnType="TVTR_T">
          <DOI name="VRtg"><SDI name="setMag"><DAI name="i"><Val>100</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>1100.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="U01C" lnClass="TVTR" inst="3" lnType="TVTR_T">
          <DOI name="VRtg"><SDI name="setMag"><DAI name="i"><Val>100</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>1100.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
        <LN prefix="U01N" lnClass="TVTR" inst="4" lnType="TVTR_T">
          <DOI name="VRtg"><SDI name="setMag"><DAI name="i"><Val>100</Val></DAI></SDI></DOI>
          <DOI name="Rat"><SDI name="setMag"><DAI name="f"><Val>1100.0</Val></DAI></SDI></DOI>
          <DOI name="HzRtg"><SDI name="setMag"><DAI name="i"><Val>50</Val></DAI></SDI></DOI>
        </LN>
      </LDevice>
    </Server></AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"/>
    <LNodeType id="TCTR_T" lnClass="TCTR"/>
    <LNodeType id="TVTR_T" lnClass="TVTR"/>
  </DataTypeTemplates>
</SCL>
