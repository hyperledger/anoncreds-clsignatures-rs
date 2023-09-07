#[cfg(feature = "serde")]
extern crate serde;

mod tests {
    use anoncreds_clsignatures::*;

    #[test]
    fn credential_with_negative_attribute_and_empty_proof_works() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        let non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        let credential_nonce = new_nonce().unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder
            .add_dec_known("height", "-1")
            .unwrap();
        let cred_values = credential_values_builder.finalize().unwrap();

        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &cred_values,
            &credential_nonce,
        )
        .unwrap();

        let cred_issuance_nonce = new_nonce().unwrap();

        let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
            "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
            &blinded_credential_secrets,
            &blinded_credential_secrets_correctness_proof,
            &credential_nonce,
            &cred_issuance_nonce,
            &cred_values,
            &cred_pub_key,
            &cred_priv_key,
        )
        .unwrap();

        Prover::process_credential_signature(
            &mut cred_signature,
            &cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &cred_issuance_nonce,
            None,
            None,
            None,
        )
        .unwrap();

        let sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_signature,
                &cred_values,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();

        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();
        assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
    }

    #[test]
    fn multiple_predicates() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder
            .add_attr("funds_sold_and_securities_purchased")
            .unwrap();
        credential_schema_builder
            .add_attr("other_earning_assets")
            .unwrap();
        credential_schema_builder.add_attr("cash").unwrap();
        credential_schema_builder.add_attr("allowance").unwrap();
        credential_schema_builder.add_attr("total_assets").unwrap();
        credential_schema_builder
            .add_attr("domestic_interest_bearing_deposits")
            .unwrap();
        credential_schema_builder
            .add_attr("funds_purchased")
            .unwrap();
        credential_schema_builder
            .add_attr("long_term_debt")
            .unwrap();
        credential_schema_builder
            .add_attr("non_interest_bearing_liabilities")
            .unwrap();
        credential_schema_builder
            .add_attr("shareholder_equity")
            .unwrap();
        credential_schema_builder
            .add_attr("total_liabilities")
            .unwrap();

        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_schema_builder
            .add_attr("master_secret")
            .unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        let link_secret = Prover::new_link_secret().unwrap();
        let credential_nonce = new_nonce().unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder
            .add_dec_known("funds_sold_and_securities_purchased", "50")
            .unwrap();
        credential_values_builder
            .add_dec_known("other_earning_assets", "60")
            .unwrap();
        credential_values_builder
            .add_dec_known("cash", "70")
            .unwrap();
        credential_values_builder
            .add_dec_known("allowance", "80")
            .unwrap();
        credential_values_builder
            .add_dec_known("total_assets", "260")
            .unwrap();

        credential_values_builder
            .add_dec_known("domestic_interest_bearing_deposits", "10")
            .unwrap();
        credential_values_builder
            .add_dec_known("funds_purchased", "20")
            .unwrap();
        credential_values_builder
            .add_dec_known("long_term_debt", "30")
            .unwrap();
        credential_values_builder
            .add_dec_known("non_interest_bearing_liabilities", "40")
            .unwrap();
        credential_values_builder
            .add_dec_known("shareholder_equity", "50")
            .unwrap();
        credential_values_builder
            .add_dec_known("total_liabilities", "150")
            .unwrap();
        let cred_values = credential_values_builder.finalize().unwrap();

        let mut blind_credential_values_builder = CredentialValuesBuilder::new().unwrap();
        blind_credential_values_builder
            .add_value_hidden("master_secret", link_secret.as_ref())
            .unwrap();
        let blind_cred_values = blind_credential_values_builder.finalize().unwrap();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &blind_cred_values,
            &credential_nonce,
        )
        .unwrap();

        let cred_issuance_nonce = new_nonce().unwrap();

        let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
            "b977afe22b5b446109797ad925d9f133fc33c1914081071295d2ac1ddce3385d",
            &blinded_credential_secrets,
            &blinded_credential_secrets_correctness_proof,
            &credential_nonce,
            &cred_issuance_nonce,
            &cred_values,
            &cred_pub_key,
            &cred_priv_key,
        )
        .unwrap();

        let prover_cred_values = cred_values.merge(&blind_cred_values).unwrap();
        Prover::process_credential_signature(
            &mut cred_signature,
            &prover_cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &cred_issuance_nonce,
            None,
            None,
            None,
        )
        .unwrap();

        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder
            .add_revealed_attr("total_liabilities")
            .unwrap();

        sub_proof_request_builder
            .add_predicate("funds_sold_and_securities_purchased", "LT", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("funds_sold_and_securities_purchased", "GT", 0)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("other_earning_assets", "LT", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("cash", "LT", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("allowance", "LT", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("total_assets", "GT", 100)
            .unwrap();

        sub_proof_request_builder
            .add_predicate("domestic_interest_bearing_deposits", "LE", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("funds_purchased", "LE", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("long_term_debt", "LE", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("non_interest_bearing_liabilities", "LE", 100)
            .unwrap();
        sub_proof_request_builder
            .add_predicate("shareholder_equity", "LE", 100)
            .unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_signature,
                &prover_cred_values,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();

        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();
        assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn credential_primary_public_key_conversion_works() {
        let string1 = r#"{
                 "n":"94752773003676215520340390286428145970577435379747248974837494389412082076547661891067434652276048522392442077335235388384984508621151996372559370276527598415204914831299768834758349425880859567795461321350412568232531440683627330032285846734752711268206613305069973750567165548816744023441650243801226580089078611213688037852063937259593837571943085718154394160122127891902723469618952030300431400181642597638732611518885616750614674142486169255034160093153314427704384760404032620300207070597238445621198019686315730573836193179483581719638565112589368474184957790046080767607443902003396643479910885086397579016949",
                 "s":"69412039600361800795429063472749802282903100455399422661844374992112119187258494682747330126416608111152308407310993289705267392969490079422545377823004584691698371089275086755756916575365439635768831063415050875440259347714303092581127338698890829662982679857654396534761554232914231213603075653629534596880597317047082696083166437821687405393805812336036647064899914817619861844092002636340952247588092904075021313598848481976631171767602864723880294787434756140969093416957086578979859382777377267118038126527549503876861370823520292585383483415337137062969402135540724590433024573312636828352734474276871187481042",
                 "r":{
                    "age":"90213462228557102785520674066817329607065098280886260103565465379328385444439123494955469500769864345819799623656302322427095342533906338563811194606234218499052997878891037890681314502037670093285650999142741875494918117023196753133733183769000368858655309319559871473827485381905587653145346258174022279515774231018893119774525087260785417971477049379955435611260162822960318458092151247522911151421981946748062572207451174079699745404644326303405628719711440096340436702151418321760375229323874027809433387030362543124015034968644213166988773750220839778654632868402703075643503247560457217265822566406481434257658",
                    "height":"5391629214047043372090966654120333203094518833743674393685635640778311836867622750170495792524304436281896432811455146477306501487333852472234525296058562723428516533641819658096275918819548576029252844651857904411902677509566190811985500618327955392620642519618001469964706236997279744030829811760566269297728600224591162795849338756438466021999870256717098048301453122263380103723520670896747657149140787953289875480355961166269553534983692005983375091110745903845958291035125718192228291126861666488320123420563113398593180368102996188897121307947248313167444374640621348136184583596487812048321382789134349482978",
                    "name":"77620276231641170120118188540269028385259155493880444038204934044861538875241492581309232702380290690573764595644801264135299029620031922004969464948925209245961139274806949465303313280327009910224580146266877846633558282936147503639084871235301887617650455108586169172459479774206351621894071684884758716731250212971549835402948093455393537573942251389197338609379019568250835525301455105289583537704528678164781839386485243301381405947043141406604458853106372019953011725448481499511842635580639867624862131749700424467221215201558826025502015289693451254344465767556321748122037274143231500322140291667454975911415",
                    "sex":"9589127953934298285127566793382980040568251918610023890115614786922171891298122457059996745443282235104668609426602496632245081143706804923757991602521162900045665258654877250328921570207935035808607238170708932487500434929591458680514420504595293934408583558084774019418964434729989362874165849497341625769388145344718883550286508846516335790153998186614300493752317413537864956171451048868305380731285315760405126912629495204641829764230906698870575251861738847175174907714361155400020318026100833368698707674675548636610079631382774152211885405135045997623813094890524761824654025566099289284433567918244183562578"
                 },
                 "rms": "51663676247842478814965591806476166314018329779100758392678204435864101706276421100107118776199283981546682625125866769910726045178868995629346547166162207336629797340989495021248125384357605197654315399409367101440127312902706857104045262430326903112478154165057770802221835566137181123204394005042244715693211063132775814710986488082414421678086296488865286754803461178476006057306298883090062534704773627985221339716152111236985859907502262026150818487846053415153813804554830872575193396851274528558072704096323791923604931528594861707067370303707070124331485728734993074005001622035563911923643592706985074084035",
                 "rctxt":"60293229766149238310917923493206871325969738638348535857162249827595080348039120693847207728852550647187915587987334466582959087190830489258423645708276339586344792464665557038628519694583193692804909304334143467285824750999826903922956158114736424517794036832742439893595716442609416914557200249087236453529632524328334442017327755310827841619727229956823928475210644630763245343116656886668444813463622336899670813312626960927341115875144198394937398391514458462051400588820774593570752884252721428948286332429715774158007033348855655388287735570407811513582431434394169600082273657382209764160600063473877124656503",
                 "z":"70486542646006986754234343446999146345523665952265004264483059055307042644604796098478326629348068818272043688144751523020343994424262034067120716287162029288580118176972850899641747743901392814182335879624697285262287085187745166728443417803755667806532945136078671895589773743252882095592683767377435647759252676700424432160196120135306640079450582642553870190550840243254909737360996391470076977433525925799327058405911708739601511578904084479784054523375804238021939950198346585735956776232824298799161587408330541161160988641895300133750453032202142977745163418534140360029475702333980267724847703258887949227842"
              }"#;

        let string2 = r#"{
                 "n":"94752773003676215520340390286428145970577435379747248974837494389412082076547661891067434652276048522392442077335235388384984508621151996372559370276527598415204914831299768834758349425880859567795461321350412568232531440683627330032285846734752711268206613305069973750567165548816744023441650243801226580089078611213688037852063937259593837571943085718154394160122127891902723469618952030300431400181642597638732611518885616750614674142486169255034160093153314427704384760404032620300207070597238445621198019686315730573836193179483581719638565112589368474184957790046080767607443902003396643479910885086397579016949",
                 "s":"69412039600361800795429063472749802282903100455399422661844374992112119187258494682747330126416608111152308407310993289705267392969490079422545377823004584691698371089275086755756916575365439635768831063415050875440259347714303092581127338698890829662982679857654396534761554232914231213603075653629534596880597317047082696083166437821687405393805812336036647064899914817619861844092002636340952247588092904075021313598848481976631171767602864723880294787434756140969093416957086578979859382777377267118038126527549503876861370823520292585383483415337137062969402135540724590433024573312636828352734474276871187481042",
                 "r":{
                    "age":"90213462228557102785520674066817329607065098280886260103565465379328385444439123494955469500769864345819799623656302322427095342533906338563811194606234218499052997878891037890681314502037670093285650999142741875494918117023196753133733183769000368858655309319559871473827485381905587653145346258174022279515774231018893119774525087260785417971477049379955435611260162822960318458092151247522911151421981946748062572207451174079699745404644326303405628719711440096340436702151418321760375229323874027809433387030362543124015034968644213166988773750220839778654632868402703075643503247560457217265822566406481434257658",
                    "height":"5391629214047043372090966654120333203094518833743674393685635640778311836867622750170495792524304436281896432811455146477306501487333852472234525296058562723428516533641819658096275918819548576029252844651857904411902677509566190811985500618327955392620642519618001469964706236997279744030829811760566269297728600224591162795849338756438466021999870256717098048301453122263380103723520670896747657149140787953289875480355961166269553534983692005983375091110745903845958291035125718192228291126861666488320123420563113398593180368102996188897121307947248313167444374640621348136184583596487812048321382789134349482978",
                    "name":"77620276231641170120118188540269028385259155493880444038204934044861538875241492581309232702380290690573764595644801264135299029620031922004969464948925209245961139274806949465303313280327009910224580146266877846633558282936147503639084871235301887617650455108586169172459479774206351621894071684884758716731250212971549835402948093455393537573942251389197338609379019568250835525301455105289583537704528678164781839386485243301381405947043141406604458853106372019953011725448481499511842635580639867624862131749700424467221215201558826025502015289693451254344465767556321748122037274143231500322140291667454975911415",
                    "sex":"9589127953934298285127566793382980040568251918610023890115614786922171891298122457059996745443282235104668609426602496632245081143706804923757991602521162900045665258654877250328921570207935035808607238170708932487500434929591458680514420504595293934408583558084774019418964434729989362874165849497341625769388145344718883550286508846516335790153998186614300493752317413537864956171451048868305380731285315760405126912629495204641829764230906698870575251861738847175174907714361155400020318026100833368698707674675548636610079631382774152211885405135045997623813094890524761824654025566099289284433567918244183562578",
                    "master_secret": "51663676247842478814965591806476166314018329779100758392678204435864101706276421100107118776199283981546682625125866769910726045178868995629346547166162207336629797340989495021248125384357605197654315399409367101440127312902706857104045262430326903112478154165057770802221835566137181123204394005042244715693211063132775814710986488082414421678086296488865286754803461178476006057306298883090062534704773627985221339716152111236985859907502262026150818487846053415153813804554830872575193396851274528558072704096323791923604931528594861707067370303707070124331485728734993074005001622035563911923643592706985074084035"
                 },
                 "rctxt":"60293229766149238310917923493206871325969738638348535857162249827595080348039120693847207728852550647187915587987334466582959087190830489258423645708276339586344792464665557038628519694583193692804909304334143467285824750999826903922956158114736424517794036832742439893595716442609416914557200249087236453529632524328334442017327755310827841619727229956823928475210644630763245343116656886668444813463622336899670813312626960927341115875144198394937398391514458462051400588820774593570752884252721428948286332429715774158007033348855655388287735570407811513582431434394169600082273657382209764160600063473877124656503",
                 "z":"70486542646006986754234343446999146345523665952265004264483059055307042644604796098478326629348068818272043688144751523020343994424262034067120716287162029288580118176972850899641747743901392814182335879624697285262287085187745166728443417803755667806532945136078671895589773743252882095592683767377435647759252676700424432160196120135306640079450582642553870190550840243254909737360996391470076977433525925799327058405911708739601511578904084479784054523375804238021939950198346585735956776232824298799161587408330541161160988641895300133750453032202142977745163418534140360029475702333980267724847703258887949227842"
              }"#;

        let one = serde_json::from_str::<CredentialPrimaryPublicKey>(string1).unwrap();
        let two = serde_json::from_str::<CredentialPrimaryPublicKey>(string2).unwrap();

        assert_eq!(two, one);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn primary_equal_proof_conversion_works() {
        let string1 = r#"{
            "revealed_attrs":{ "name":"1139481716457488690172217916278103335" },
            "a_prime":"73051896986344783783621559954466052240337632808477729510525777007534198657123370460809453476237905269777928500034476888078179811369103091702326392092669222868996323974762333077146800752404116534730748685092400106417894776122280960547391515814302192999142386455183675790870578615457141270148590712693325301185445330992767208427208215818892089082206123243055148017865514286222759353929656015594529211154843197464055996993778878163967106658629893439206203941596066380562586058713924055616953462170537040600604826428201808405436865130230174790116739542071871153581967170346076628186863101926791732126528122264782281465094",
            "e":"26894279258848531841414955598838798345606055130059418263879278878511424413654641307014787224496208858379991228288791608261549931755104416",
            "v":"769593829417540943566687651216000708099616242062220026508500847265211856977241087739974159673381844796906987056271685312217722655254322996792650873775611656861273544234724432321045515309211146266498852589181986850053751764534235454974453901933962390148609111520973909072559803423360526975061164422239685006387576029266210201929872373313392190241424322333321394922891207577033519614434276723347140746548441162607411616008633618021962845423830579218345578253882839612570986096830936195064001459565147361336597305783767484298283647710212770870573787603073109857430854719681849489345098539472090186844042540487233617799636327572785715912348265648433678177765454231546725849288046905854444755145184654162149010359429569273734847400697627028832950969890252877892391103230391674009825009176344665382964776819962789472959504523580584494299815960094679820651071251157496967617834816772303813309035759721203718921501821175528106375",
            "m":{
                "age":"1143281854280323408461665818853228702279803847691030529301464848501919856277927436364331044530711281448694432838145799412204154542183613877104383361274202256495017144684827419222",
                "sex":"13123681697669364600723785784083768668401173003182555407713667959884184961072036088391942098105496874381346284841774772987179772727928471347011107103459387881602408580853389973314",
                "height":"5824877563809831190436025794795529331411852203759926644567286594845018041324472260994302109635777382645241758582661313361940262319244084725507113643699421966391425299602530147274"
             },
             "m1":"8583218861046444624186479147396651631579156942204850397797096661516116684243552483174250620744158944865553535495733571632663325011575249979223204777745326895517953843420687756433",
             "m2":"5731555078708393357614629066851705238802823277918949054467378429261691189252606979808518037016695141384783224302687321866277811431449642994233365265728281815807346591371594096297"
         }"#;
        let string2 = r#"{
            "revealed_attrs":{ "name":"1139481716457488690172217916278103335" },
            "a_prime":"73051896986344783783621559954466052240337632808477729510525777007534198657123370460809453476237905269777928500034476888078179811369103091702326392092669222868996323974762333077146800752404116534730748685092400106417894776122280960547391515814302192999142386455183675790870578615457141270148590712693325301185445330992767208427208215818892089082206123243055148017865514286222759353929656015594529211154843197464055996993778878163967106658629893439206203941596066380562586058713924055616953462170537040600604826428201808405436865130230174790116739542071871153581967170346076628186863101926791732126528122264782281465094",
            "e":"26894279258848531841414955598838798345606055130059418263879278878511424413654641307014787224496208858379991228288791608261549931755104416",
            "v":"769593829417540943566687651216000708099616242062220026508500847265211856977241087739974159673381844796906987056271685312217722655254322996792650873775611656861273544234724432321045515309211146266498852589181986850053751764534235454974453901933962390148609111520973909072559803423360526975061164422239685006387576029266210201929872373313392190241424322333321394922891207577033519614434276723347140746548441162607411616008633618021962845423830579218345578253882839612570986096830936195064001459565147361336597305783767484298283647710212770870573787603073109857430854719681849489345098539472090186844042540487233617799636327572785715912348265648433678177765454231546725849288046905854444755145184654162149010359429569273734847400697627028832950969890252877892391103230391674009825009176344665382964776819962789472959504523580584494299815960094679820651071251157496967617834816772303813309035759721203718921501821175528106375",
            "m":{
                "age":"1143281854280323408461665818853228702279803847691030529301464848501919856277927436364331044530711281448694432838145799412204154542183613877104383361274202256495017144684827419222",
                "sex":"13123681697669364600723785784083768668401173003182555407713667959884184961072036088391942098105496874381346284841774772987179772727928471347011107103459387881602408580853389973314",
                "height":"5824877563809831190436025794795529331411852203759926644567286594845018041324472260994302109635777382645241758582661313361940262319244084725507113643699421966391425299602530147274",
                "master_secret":"8583218861046444624186479147396651631579156942204850397797096661516116684243552483174250620744158944865553535495733571632663325011575249979223204777745326895517953843420687756433"
             },
             "m2":"5731555078708393357614629066851705238802823277918949054467378429261691189252606979808518037016695141384783224302687321866277811431449642994233365265728281815807346591371594096297"
         }"#;

        let one = serde_json::from_str::<PrimaryEqualProof>(string1).unwrap();
        let two = serde_json::from_str::<PrimaryEqualProof>(string2).unwrap();

        assert_eq!(two, one);
    }

    #[test]
    fn demo() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_schema_builder
            .add_attr("master_secret")
            .unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        let link_secret = Prover::new_link_secret().unwrap();
        let credential_nonce = new_nonce().unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder
            .add_dec_known("name", "1139481716457488690172217916278103335")
            .unwrap();
        credential_values_builder
            .add_dec_known(
                "sex",
                "5944657099558967239210949258394887428692050081607692519917050011144233115103",
            )
            .unwrap();
        credential_values_builder
            .add_dec_known("age", "28")
            .unwrap();
        credential_values_builder
            .add_dec_known("height", "175")
            .unwrap();
        let cred_values = credential_values_builder.finalize().unwrap();

        let mut blind_credential_values_builder = CredentialValuesBuilder::new().unwrap();
        blind_credential_values_builder
            .add_value_hidden("master_secret", link_secret.as_ref())
            .unwrap();
        let blind_cred_values = blind_credential_values_builder.finalize().unwrap();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &blind_cred_values,
            &credential_nonce,
        )
        .unwrap();

        let cred_issuance_nonce = new_nonce().unwrap();

        let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
            "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
            &blinded_credential_secrets,
            &blinded_credential_secrets_correctness_proof,
            &credential_nonce,
            &cred_issuance_nonce,
            &cred_values,
            &cred_pub_key,
            &cred_priv_key,
        )
        .unwrap();

        let prover_cred_values = cred_values.merge(&blind_cred_values).unwrap();
        Prover::process_credential_signature(
            &mut cred_signature,
            &prover_cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &cred_issuance_nonce,
            None,
            None,
            None,
        )
        .unwrap();

        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder
            .add_predicate("age", "GE", 18)
            .unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_signature,
                &prover_cred_values,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();

        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_pub_key,
                None,
                None,
            )
            .unwrap();
        assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
    }

    #[test]
    fn demo_revocation() {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_schema_builder
            .add_attr("master_secret")
            .unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, true).unwrap();

        let max_cred_num = 5;
        let issuance_by_default = false;
        let (rev_key_pub, rev_key_priv, mut rev_reg, _rev_tails_generator) =
            Issuer::new_revocation_registry_def(&cred_pub_key, max_cred_num, issuance_by_default)
                .unwrap();

        let link_secret = Prover::new_link_secret().unwrap();

        let credential_nonce = new_nonce().unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder
            .add_dec_known("name", "1139481716457488690172217916278103335")
            .unwrap();
        credential_values_builder
            .add_dec_known(
                "sex",
                "5944657099558967239210949258394887428692050081607692519917050011144233115103",
            )
            .unwrap();
        credential_values_builder
            .add_dec_known("age", "28")
            .unwrap();
        credential_values_builder
            .add_dec_known("height", "175")
            .unwrap();
        let cred_values = credential_values_builder.finalize().unwrap();

        let mut blind_credential_values_builder = CredentialValuesBuilder::new().unwrap();
        blind_credential_values_builder
            .add_value_hidden("master_secret", link_secret.as_ref())
            .unwrap();
        let blind_cred_values = blind_credential_values_builder.finalize().unwrap();
        let (
            blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &blind_cred_values,
            &credential_nonce,
        )
        .unwrap();

        let credential_issuance_nonce = new_nonce().unwrap();

        let rev_idx = 1;
        let (mut cred_signature, signature_correctness_proof, witness, _rev_reg_delta) =
            Issuer::sign_credential_with_revoc(
                "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &cred_values,
                &cred_pub_key,
                &cred_priv_key,
                rev_idx,
                max_cred_num,
                issuance_by_default,
                &mut rev_reg,
                &rev_key_priv,
            )
            .unwrap();

        let prover_cred_values = cred_values.merge(&blind_cred_values).unwrap();
        Prover::process_credential_signature(
            &mut cred_signature,
            &prover_cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &credential_issuance_nonce,
            Some(&rev_key_pub),
            Some(&rev_reg),
            Some(&witness),
        )
        .unwrap();

        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("name").unwrap();
        sub_proof_request_builder
            .add_predicate("age", "GE", 18)
            .unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_signature,
                &prover_cred_values,
                &cred_pub_key,
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();
        let proof_request_nonce = new_nonce().unwrap();
        let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier
            .add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &cred_pub_key,
                Some(&rev_key_pub),
                Some(&rev_reg),
            )
            .unwrap();
        assert_eq!(
            true,
            proof_verifier.verify(&proof, &proof_request_nonce).unwrap()
        );
    }
}

#[cfg(feature = "openssl_bn")]
mod openssl_tests {
    use anoncreds_clsignatures::*;
    use std::collections::BTreeSet;

    pub const PROVER_ID: &'static str = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";
    // Master secret is now called link secret.
    pub static LINK_SECRET: &'static str = "master_secret";

    mod test {
        use super::*;

        #[test]
        fn anoncreds_demo() {
            // // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();

            // Issuer creates GVT credential
            // 2. Issuer creates GVT credential schema
            let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            credential_schema_builder.add_attr("name").unwrap();
            credential_schema_builder.add_attr("sex").unwrap();
            credential_schema_builder.add_attr("age").unwrap();
            credential_schema_builder.add_attr("height").unwrap();
            let gvt_credential_schema = credential_schema_builder.finalize().unwrap();

            let mut non_credential_schema_builder =
                Issuer::new_non_credential_schema_builder().unwrap();
            non_credential_schema_builder
                .add_attr("master_secret")
                .unwrap();
            let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

            // 3. Issuer creates GVT credential definition
            let (
                gvt_credential_pub_key,
                gvt_credential_priv_key,
                gvt_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, true)
                .unwrap();

            // 4. Issuer creates GVT revocation registry with IssuanceOnDemand type
            let gvt_max_cred_num = 5;
            let gvt_issuance_by_default = false;
            let (gvt_rev_key_pub, gvt_rev_key_priv, mut gvt_rev_reg, _gvt_rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &gvt_credential_pub_key,
                    gvt_max_cred_num,
                    gvt_issuance_by_default,
                )
                .unwrap();

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let gvt_credential_nonce = new_nonce().unwrap();

            // 6. Issuer creates GVT credential values
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_dec_known("name", "1139481716457488690172217916278103335")
                .unwrap();
            credential_values_builder
                .add_dec_known(
                    "sex",
                    "5944657099558967239210949258394887428692050081607692519917050011144233115103",
                )
                .unwrap();
            credential_values_builder
                .add_dec_known("age", "28")
                .unwrap();
            credential_values_builder
                .add_dec_known("height", "175")
                .unwrap();
            let gvt_credential_values = credential_values_builder.finalize().unwrap();

            // 7. Prover blinds hidden attributes
            let mut blind_credential_values_builder = CredentialValuesBuilder::new().unwrap();
            blind_credential_values_builder
                .add_value_hidden("master_secret", link_secret.as_ref())
                .unwrap();
            let gvt_blind_credential_values = blind_credential_values_builder.finalize().unwrap();
            let (
                gvt_blinded_credential_secrets,
                gvt_credential_secrets_blinding_factors,
                gvt_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &gvt_credential_key_correctness_proof,
                &gvt_blind_credential_values,
                &gvt_credential_nonce,
            )
            .unwrap();

            // 8. Prover creates nonce used by Issuer to create correctness proof for signature
            let gvt_credential_issuance_nonce = new_nonce().unwrap();

            // 9. Issuer signs GVT credential values
            let gvt_rev_idx = 1;
            let (
                mut gvt_credential_signature,
                gvt_signature_correctness_proof,
                gvt_witness,
                _gvt_rev_reg_delta,
            ) = Issuer::sign_credential_with_revoc(
                PROVER_ID,
                &gvt_blinded_credential_secrets,
                &gvt_blinded_credential_secrets_correctness_proof,
                &gvt_credential_nonce,
                &gvt_credential_issuance_nonce,
                &gvt_credential_values,
                &gvt_credential_pub_key,
                &gvt_credential_priv_key,
                gvt_rev_idx,
                gvt_max_cred_num,
                gvt_issuance_by_default,
                &mut gvt_rev_reg,
                &gvt_rev_key_priv,
            )
            .unwrap();

            // 10. Prover processes GVT credential signature
            let gvt_prover_cred_values = gvt_credential_values
                .merge(&gvt_blind_credential_values)
                .unwrap();
            Prover::process_credential_signature(
                &mut gvt_credential_signature,
                &gvt_prover_cred_values,
                &gvt_signature_correctness_proof,
                &gvt_credential_secrets_blinding_factors,
                &gvt_credential_pub_key,
                &gvt_credential_issuance_nonce,
                Some(&gvt_rev_key_pub),
                Some(&gvt_rev_reg),
                Some(&gvt_witness),
            )
            .unwrap();

            // Issuer creates XYZ credential
            // 11. Issuer creates XYZ credential schema
            let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            credential_schema_builder.add_attr("period").unwrap();
            credential_schema_builder.add_attr("status").unwrap();
            let xyz_credential_schema = credential_schema_builder.finalize().unwrap();

            // 12. Issuer creates XYZ credential definition (with revocation keys)
            let (
                xyz_credential_pub_key,
                xyz_credential_priv_key,
                xyz_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&xyz_credential_schema, &non_credential_schema, true)
                .unwrap();

            // 13. Issuer creates XYZ revocation registry with IssuanceByDefault type
            let xyz_max_cred_num = 5;
            let xyz_issuance_by_default = true;
            let (xyz_rev_key_pub, xyz_rev_key_priv, mut xyz_rev_reg, _xyz_rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &xyz_credential_pub_key,
                    xyz_max_cred_num,
                    xyz_issuance_by_default,
                )
                .unwrap();

            // 14. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let xyz_credential_nonce = new_nonce().unwrap();

            // 15. Issuer creates XYZ credential values
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_dec_known("status", "51792877103171595686471452153480627530895")
                .unwrap();
            credential_values_builder
                .add_dec_known("period", "8")
                .unwrap();
            let xyz_credential_values = credential_values_builder.finalize().unwrap();

            // 16. Prover blinds hidden attributes
            let mut blind_credential_values_builder = CredentialValuesBuilder::new().unwrap();
            blind_credential_values_builder
                .add_value_hidden("master_secret", link_secret.as_ref())
                .unwrap();
            let xyz_blind_credential_values = blind_credential_values_builder.finalize().unwrap();
            let (
                xyz_blinded_credential_secrets,
                xyz_credential_secrets_blinding_factors,
                xyz_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &xyz_credential_pub_key,
                &xyz_credential_key_correctness_proof,
                &xyz_blind_credential_values,
                &xyz_credential_nonce,
            )
            .unwrap();

            // 17. Prover creates nonce used by Issuer to create correctness proof for signature
            let xyz_credential_issuance_nonce = new_nonce().unwrap();

            // 18. Issuer signs XYZ credential values
            let xyz_rev_idx = 1;
            let (
                mut xyz_credential_signature,
                xyz_signature_correctness_proof,
                xyz_witness,
                xyz_rev_reg_delta,
            ) = Issuer::sign_credential_with_revoc(
                PROVER_ID,
                &xyz_blinded_credential_secrets,
                &xyz_blinded_credential_secrets_correctness_proof,
                &xyz_credential_nonce,
                &xyz_credential_issuance_nonce,
                &xyz_credential_values,
                &xyz_credential_pub_key,
                &xyz_credential_priv_key,
                xyz_rev_idx,
                xyz_max_cred_num,
                xyz_issuance_by_default,
                &mut xyz_rev_reg,
                &xyz_rev_key_priv,
            )
            .unwrap();
            assert!(xyz_rev_reg_delta.is_none());

            // 19. Prover processes XYZ credential signature
            let xyz_prover_cred_values = xyz_credential_values
                .merge(&xyz_blind_credential_values)
                .unwrap();
            Prover::process_credential_signature(
                &mut xyz_credential_signature,
                &xyz_prover_cred_values,
                &xyz_signature_correctness_proof,
                &xyz_credential_secrets_blinding_factors,
                &xyz_credential_pub_key,
                &xyz_credential_issuance_nonce,
                Some(&xyz_rev_key_pub),
                Some(&xyz_rev_reg),
                Some(&xyz_witness),
            )
            .unwrap();

            // 20. Verifier creates sub proof request related to GVT credential
            let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
            sub_proof_request_builder.add_revealed_attr("name").unwrap();
            sub_proof_request_builder
                .add_predicate("age", "GE", 18)
                .unwrap();
            let gvt_sub_proof_request = sub_proof_request_builder.finalize().unwrap();

            // 21. Verifier creates sub proof request related to XYZ credential
            let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
            sub_proof_request_builder
                .add_revealed_attr("status")
                .unwrap();
            sub_proof_request_builder
                .add_predicate("period", "GE", 4)
                .unwrap();
            let xyz_sub_proof_request = sub_proof_request_builder.finalize().unwrap();

            // 22. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 23. Prover creates proof for two sub proof requests
            let mut proof_builder = Prover::new_proof_builder().unwrap();

            proof_builder.add_common_attribute(LINK_SECRET).unwrap();
            proof_builder
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_signature,
                    &gvt_prover_cred_values,
                    &gvt_credential_pub_key,
                    Some(&gvt_rev_reg),
                    Some(&gvt_witness),
                )
                .unwrap();

            proof_builder
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_signature,
                    &xyz_prover_cred_values,
                    &xyz_credential_pub_key,
                    Some(&xyz_rev_reg),
                    Some(&xyz_witness),
                )
                .unwrap();

            let proof = proof_builder.finalize(&nonce).unwrap();

            // 24. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_pub_key,
                    Some(&gvt_rev_key_pub),
                    Some(&gvt_rev_reg),
                )
                .unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_pub_key,
                    Some(&xyz_rev_key_pub),
                    Some(&xyz_rev_reg),
                )
                .unwrap();

            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn credential_with_negative_attribute_and_empty_proof_works() {
            let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            credential_schema_builder.add_attr("height").unwrap();
            let credential_schema = credential_schema_builder.finalize().unwrap();

            let non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
            let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

            let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            let credential_nonce = new_nonce().unwrap();

            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_dec_known("height", "-1")
                .unwrap();
            let cred_values = credential_values_builder.finalize().unwrap();

            let blind_cred_values = CredentialValues::default();
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &cred_pub_key,
                &cred_key_correctness_proof,
                &blind_cred_values,
                &credential_nonce,
            )
            .unwrap();

            let cred_issuance_nonce = new_nonce().unwrap();

            let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
                "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &cred_issuance_nonce,
                &cred_values,
                &cred_pub_key,
                &cred_priv_key,
            )
            .unwrap();

            Prover::process_credential_signature(
                &mut cred_signature,
                &cred_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &cred_pub_key,
                &cred_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
            sub_proof_request_builder
                .add_predicate("height", "GE", -2)
                .unwrap();
            let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &cred_signature,
                    &cred_values,
                    &cred_pub_key,
                    None,
                    None,
                )
                .unwrap();

            let proof_request_nonce = new_nonce().unwrap();
            let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &cred_pub_key,
                    None,
                    None,
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_primary_proof_only() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Issuer creates credential values
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds hidden attributes
            let link_secret = Prover::new_link_secret().unwrap();
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Verifier create sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 10. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 11. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values.merge(&blind_credential_values).unwrap(),
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_issuance_on_demand() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry with IssuanceOnDemand type
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, _rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            // 4. Issuer creates and sign credential values
            let credential_values = helpers::gvt_credential_values();

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds hidden attributes
            let link_secret = Prover::new_link_secret().unwrap();
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, witness, _rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();

            // 9. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 10. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 11. Verifier create sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 12. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values.merge(&blind_credential_values).unwrap(),
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 13. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_issuance_by_default() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 4. Issuer creates GVT revocation registry with IssuanceByDefault type
            let max_cred_num = 5;
            let issuance_by_default = true;
            let (rev_key_pub, rev_key_priv, mut rev_reg, _rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            // 4. Prover creates master secret with credential values
            let credential_values = helpers::gvt_credential_values();

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 8. Issuer creates and sign credential values
            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, witness, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();
            assert!(rev_reg_delta.is_none());
            // let rev_reg_delta = RevocationRegistryDelta::from(&rev_reg);

            // 9. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 10. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 11. Verifier create sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 12. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values.merge(&blind_credential_values).unwrap(),
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 13. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[cfg(feature = "serde")]
        #[test]
        fn anoncreds_works_for_unlinked_revocation_proof() {
            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            // let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            //     Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
            //         .unwrap();

            let credential_pub_key: CredentialPublicKey = serde_json::from_str(
                "{\"p_key\":{\"n\":\"1036729576768817628450252957770265467918077312326138\
                941951996958949507202362805399981219578727241125149291910613725193701072\
                370623781805071141071223994251001800379496680295443054128919163648727326\
                837515016025798081726164968317807760046317502929100835105525527472010795\
                809944929588563197828301387613648537451633506309702223319182324912403320\
                439595498315549054162417500029008885818845996057452936672928297629447807\
                996897228156083303073707939599039412977525324116132555345798752992565312\
                523871656988069060201815241102525531640694272215774900996455009329712281\
                94449878776712397984193175906407140831928663477294274959258741\",\"s\":\"\
                330153922791989232122552092833948084508607487599495682348127335522540215\
                428154804495683913488645189640308927001033539989746364311887212616917495\
                107172618734458889175903373840894167510525455906523740427100340903290506\
                915923052441157481410385621726694745564514778792585240122265367614612485\
                168598557141446337822569757868839330395045169723647167298334704083777752\
                301031288174212707644007833037032160427511717351698706790431379478306577\
                622648114608028581986934841917526698890575160373564009657284572352051152\
                735347783065128149162507431547529705076647604401266741035185526160151506\
                54455788870108395701918375305577754098532\",\"r\":{\"sex\":\"96965492943\
                144266864078689223719761476416250314053808704761660144700538419581623024\
                756427297547039259869632499322712461786760970903897949725915476694695262\
                386358602722890263398851433141931401196216295233932298080167266010105743\
                704005081747597022233852806126311861001569548603202689658520067067132555\
                157320236861441180971823286281719766268528790369974158802445880022151179\
                479138668648178982257278927391086640411749165963964371618869051043708780\
                354648050825976938450222354358058504817125182495244294100301076407261313\
                836507802697635652625031779938070889926223220136606546468402667030901417\
                64105113951786838652119453833\",\"name\":\"10088644580022855941721218361\
                058411774568352023284845272664620230710200082872025907060684522204466424\
                687900621015165341341393382397493894369656868264601478658774265329906139\
                337770020973379433242244506735665361944303695730603545058433298179269967\
                464997575680987241855047991312242476309058365722122703673357878293385765\
                720757057049990574967136378406558433147793818888945346078961043065022952\
                425554644699484079550693851016817302046843103669280796702244715265137055\
                423262230947950204353695762702626080046870279624833963102861945223676672\
                076503163567583959696762885746763929838618274169832638934912474145404596\
                7590504257060\",\"master_secret\":\"238433370567044241265482165896669098\
                606974675097763621057397397812981584981865743863849521977346409273909255\
                816576322843784196277288580668416651698848480488277582660341343926594766\
                032242209852623891876998636313220696944042427554509667648247547072298029\
                179176861096896887724950962472206197228535418799840450936828233833461421\
                799732545863941578138171085065955745610866529455220129113248411807996439\
                556677926401716804341770539796446446174361307164027180439323453191709191\
                693411920915912751559733015062212657891584181660399619293817406767872952\
                669023194441829295197043630249535832726582373089243559768841850695088469\
                84616\",\"height\":\"299123515663424586830688655160513222083921661234792\
                198979617413695261037698646068517762461639623326126299918032878912190325\
                602436964940477004994889932045514160611614912318266605170716207252274035\
                375906669074711765912234625815267199605789291751083274117125253915185663\
                090490506066892484751480061087876056000699296745807722851415228642194160\
                066486914602987386898472172326162572104022595298585701264659905698652684\
                182786214556113060430875682506051229580931418274384713612301687560688956\
                442083567625913235370290271422987296226757411224203387834450888019354130\
                64521159880823692836380045704445203353123972275393468077707775\",\"age\"\
                :\"383442339158796268297332857642191512286154841382333352845946010136737\
                733978022298013630998625671716223834160412089492014885979379943135465441\
                720847076663334155841903737341917913942330218731108995536831774276789085\
                738400090504459512890794338360385688262823255753868812269413733835098486\
                851187864417876334017763083745251435617761634420075043524169312942692062\
                444991325348802493708025766690193243908082704021679793282471128706628970\
                363692779612372811456937357588235607552393607932298755028406240032514199\
                001282529660397934261887461439786876648030146112788077723044541633074390\
                20301482304167459268746471354697753780191698\"},\"rctxt\":\"477358642762\
                253876229654167701994154539677599795269335233128981883718447895383124562\
                906409453690753135209490623669742087307905649351833358723394777969676271\
                988855861868142381793819742146807092890567697639035967997956527682949995\
                498773125356054735244981938327173477293976228371273867773341681887493779\
                393154293562985430304743745455149207524269497584819468904636364312979458\
                122367100798281626306859211459267556344886353969200198969401090290567134\
                196507268807181237532778150453928910523784343298480502551732504433208329\
                960979021920075027441560964851064764379354530541416502994574963125626251\
                39002791579103098810750148917\",\"z\":\"41065236777767395888798256461954\
                389002217989227780730861658899113676918473778493848230807420443465594988\
                123367333677735586884344285892645498914034905034591780575500141755820641\
                137427238941839031933260631734813664110955904380274326703490429785236527\
                867454436544553595259895427071513844285732783673545480340664702950477370\
                894247516830719500482750842810188848128383820742334130549586471230739665\
                811129826143752333970685478866298025827647946515701634133982398962641635\
                664562459885380406389877101675866929832720589545224356737325499046127094\
                059550244384663169519991651722520609912787987722379759927028341042404114\
                028231704\"},\"r_key\":{\"g\":\"1 1A487893DC78CE06A92DD07DC158E6E533449E\
                458882A9A1E12E1432F2CC6853 1 1153F876469F40393F0F785593E954C3DB0D14F7F19\
                1F41C86C6FF7F57FDBEE6 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F\
                07FFFFFF7D07A8A8\",\"g_dash\":\"1 0FBFD18603CF6B67721409B10B6BCD40E7EFB7\
                E21999E0DC510C7FB4BE11D613 1 05D5CC24CBEAAA46672702235965EBAF94DD417DA96\
                A0134515A21643B154C2B 1 130FBC62F1DB20EC7BF4A83C3FD675C7A83DEEF8DF8AD4C4\
                453B912307525E6A 1 0845A2C4B659723F030A99CFDD0539F435473A362CCC6F2DF8CCF\
                D616085938A 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D\
                07A8A8 1 000000000000000000000000000000000000000000000000000000000000000\
                0\",\"h\":\"1 1E53F5D39D318815C08822D256DC89337D92727673BB8D3576A3E0369D\
                A15960 1 135251080BAE27DC73E5DBCE5239CB1DFFB75A094CCDED616B7BCC66F0773B0\
                6 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8\",\"\
                h0\":\"1 1FCA595184A460D47E0FB5296F405FB545D943C1E78A9B8AE9EE5D0721271D8\
                D 1 0E42A843BFDB9D2A38AB8419319459FF017E96C4DA334C9F78E96D74091E1358 2 0\
                95E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8\",\"h1\"\
                :\"1 21AA32D914475D69F2F1BDF80E41FA92C879963DDF72CEECE772EB08D688F24E 1 \
                07C46C9A267E2E799F30E7213AC889A6AA8080AC00A360083376C56050529C06 2 095E4\
                5DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8\",\"h2\":\"1 \
                129E0BB39C1A59427423F839F83F2195EF090EF5E574EFA042B9F469F6342E87 1 1E17\
                E87AE97F74358F9140AF49C0C2CF5CC0794F26207E064A26262C2CDF6AFE 2 095E45DDF\
                417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8\",\"htilde\":\"1 \
                13FF2B875913DCB1BC7910BB01E5EC90F6EE19746D8B4405C3F98F74745592D1 1 22DF\
                DE59D40FA18A63AA709858CAC5D0D852293E58193AA5D2F817EBA285D6D9 2 095E45DDF\
                417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8\",\"h_cap\":\"1 \
                22EAFF819FDCD7CA79C0C2C2DF2C4180A4FF68D31E80BEA638AF54031B4CDDD7 1 10310\
                8FB1B65E789C1E71FF55198D854564CE2100FDAEFC2876276BB655B9DD8 1 10BEEA3BFA\
                8164658E020951B3B23FF23041DA02F66CF42C731304DBF771E12B 1 1D3769CD47E9AAE\
                92E0A5F110CB77B07933882317160DCAC1AA2584A700EE806 2 095E45DDF417D05FB109\
                33FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000\
                000000000000000000000000000000000000000\",\"u\":\"1 0DD40C82930105A9EBF7\
                CF3110029A9F09955A4CAC2F8DFD6B71EC0C716084D3 1 1D3AB4B0E9A13062B706A0C94\
                C4F0336074A195867A7DBEBBD57B33A2E0F5F47 1 0851686F89F643108142C75431CD02\
                1D3213D1856E78DB318A57F68AAE1FB049 1 08F1DCB5C725E803353D725C4C9F5130ACB\
                7BB24CF60DC58A179439724458F92 2 095E45DDF417D05FB10933FFC63D474548B7FFFF\
                7888802F07FFFFFF7D07A8A8 1 000000000000000000000000000000000000000000000\
                0000000000000000000\",\"pk\":\"1 01E9E49513F12E28761D568DA86CDC0D294688D\
                222CCDA41D85E09BE1D691DDC 1 1BB788B08F063F9A8785A8CDCC38D51E57CD2410F071\
                0E605E02C0E13AA32F17 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F0\
                7FFFFFF7D07A8A8\",\"y\":\"1 11D0AD8A036FFEEA6171AFE43B8070377E1F88902A88\
                CA5AE958C9CAFE9A1F05 1 13BFCC4D17F00256395031C749F57CA48186BE2B310A4062E\
                61E3A935D46C71A 1 0797DB25ACE7CA5C35839ECE11BCFBAF8864C5E709ADFDF5FF68B8\
                682FBC1357 1 094EC8B3D8832FF74C20224D269805E72BE21757DD9305A21A5C0851A81\
                1BB1F 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 \
                1 0000000000000000000000000000000000000000000000000000000000000000\"}}",
            )
            .unwrap();

            let rev_key_pub: RevocationKeyPublic = serde_json::from_str(
                "{\"z\":\"1 163E306C543C418B89A44CF0A6B785C79973149A0C600C85256B10633D014\
                D30 1 122A64844C9CCA70996B409BEB0C0CEC02BD427BE704692E971113EDED8BD6B2 1 \
                245B4FB6C0A8AC3FDD36779EE747642450B8F42DB56AAD4B988EA04DA4C8C7D0 1 16AD\
                56A0F450F9AE814E47BEB6BC4794571638908B5C14FE5B2FF64262939D24 1 2340956BC\
                DA89D632C8C1EF8B1504CA916E24C3A2D38205454B6472654A3FFD1 1 0B388812CD3A0C\
                89315F2E843139533063CA1CD3F7F545F9F2A10E897F9B4691 1 1B5DF08FA24BF08E5F5\
                E8015840464EEA437F00ABC7648D9BB17507C103077A1 1 220B038C0FD8CD3B488109E2\
                705C8F3303D2DE622063CD17A32CABF8AC4337D7 1 14BF4FE8F72FA784513C41D4A6334\
                6B2AB3974CAE77C46D5C514E27BB227AFC1 1 0960990790FBD7210D2DFDD86CE26A8570\
                DCD9F656B0787D9BCE7B0E3313B5F9 1 107145A3122BE1AFDCB329F0D472AE2E53A6477\
                F56800351AC118C469A9F4FB9 1 000C8B9F5FFF2FEC593C03BD8828E91111690A147B42\
                3B278531110EC7AFC217\"}",
            )
            .unwrap();

            let nonce: Nonce = serde_json::from_str("\"739809571684139146171303\"").unwrap();

            let rev_reg: RevocationRegistry = serde_json::from_str(
                "{\"accum\":\"1 00C7BBCE21E0AE8CD10822A5D5D6F40C9F651038AFB0313A770DF81D5\
                70D0998 1 1D9317A307943F3232C735BA4CAF074C11EB645B4EAB7144740565B2882AC7\
                17 1 066153AAEC91D7177506B738A05184B9E4F59606A27769EDAF91BD3045C340B8 1 \
                11C357A3A07BFFBD2D3D3D449ABB4A262B939879B610033D6076D5750EE36E8B 2 095E4\
                5DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000\
                000000000000000000000000000000000000000000000000000000\"}",
            )
            .unwrap();

            let proof: Proof = serde_json::from_str(
                "{\"proofs\":[{\"primary_proof\":{\"eq_proof\":{\"revealed_attrs\":{\"nam\
                e\":\"1139481716457488690172217916278103335\"},\"a_prime\":\"28354151628\
                427223522387250064372660071371174439391361309836487357986467847205320357\
                512245716828689785886565813939854888585473190818912382323702924499414503\
                892531158464790449537005944353911457820936816956153897826830600777841089\
                766486519337707986512839762210837294730586333497175699066544628946688288\
                976104944628193744080035506348222234179033341844644390986653085826091610\
                558312912277074746081513675477623121077576292716772206610194575015929064\
                177893663051875005871997774609422141965990811402704179025979082100091326\
                411542099509112459920097178756893013917680309016524525407605150466982947\
                540448581730532966529347743247\",\"e\":\"1734905634925213641206583507221\
                069576445828228492627922648204178285541611243899723348868493585151642408\
                06017933377349061682754752239282486\",\"v\":\"73541805813361094872542841\
                160780855479384111001439830442719854868455299536026295671496152689809952\
                165592792664250608689464934426127389967621887974089611431865304100467043\
                098368298109166156290823631375169226935842716748490964620121640890478763\
                941410225516180130937835608955472410956155125479104871754076425500286490\
                370388064977966480489203426836144526127492398574744804119032841705760183\
                381937760160529673294720172811394801758678921794071144173291766110129940\
                599661022504063592281043804214215613701484448340676422643421375875356682\
                703895279335970073720904564379236890782993276909298374415074591236828818\
                215114608292382813502697832659876789338561959598842934857986457869368220\
                155528193937331070910254897863280456355376844968806240558606203217232662\
                536610145111483767380821644613338019890882643736360351116316915243539616\
                146804071159177751253451279159039788958029117089771186371846432112451288\
                2602724137599305496222778165998\",\"m\":{\"age\":\"134264483867040521224\
                365083684126492822473030060331626994274500019598964405743277890392690697\
                574204621574111777138569674090458870681408897310436895943170984961168631\
                39661748333083\",\"sex\":\"101765340444886616579036684372760038201237241\
                268188205697776496256775199421244685884935309913238641172512933939887840\
                36518322836676734527393595887969708495010362172038862116784401\",\"maste\
                r_secret\":\"31181872484329610534842554104322260121110281276802204082149\
                973500753614204408220385147778461425227561969983322588547295582608303541\
                74879261451123802441855944904435170250049866268\",\"height\":\"161661671\
                278315633326588985563718429251696074815073701912732904911107076610245218\
                666790560094903901268362330857276790378818525660007712871700855749984152\
                50022948192280602167273431\"},\"m2\":\"158370668393625738783830956221663\
                068560731241417240583650700927030966020268508490249550694340176465647215\
                5376624499916051175741866801469645227220300450880\"},\"ge_proofs\":[{\"u\
                \":{\"0\":\"117250836537070643726310029918697747523120394751919390670560\
                320544273799039476888898700496617831908369009329336017275001465029179359\
                13243102088147328829787341779178860141106747948\",\"1\":\"97054129082590\
                976812640974827665480983637848319066651148342208907892508012066096194958\
                735506531828998389691256605973463454518906031327584563801385837761430222\
                06520953729449445089\",\"2\":\"14389486352828349929753868958247158568247\
                006527103767760918614139129649079553974239486845923363313057521321913419\
                299011247231304057328091278276048927734401139145672060365377084896\",\"3\
                \":\"3772196979051460892485565404461579243843784994811239245335877885571\
                444950666487133704362026933208214425219184460975786711017042604868687333\
                670893544423225733443121070067022959734\"},\"r\":{\"DELTA\":\"1312308292\
                820352755290648526733593856346504978004498701965469598164332962580453296\
                656327892175926430603351912673617478208313463786759760570833346718508579\
                241881968729518316319502635111875169832503839751164374800808843309820965\
                218086027191518578761059914943269972832588203529068803678779356216991561\
                622927542610512639803999768826709978582193159465886775466082656844428366\
                555956312695947923841694812764706083563119967372867087767725567157025840\
                125292984666592031756629971131512846916064582928418323277308282170015239\
                744317055695571910944729158366021491924906216610590413441113561600729286\
                117563727234944933682286933740599565033383719613618031416282291102356302\
                1514503805321215171210756032289117371871836666421491116389\",\"0\":\"434\
                479315847804900082728189855304140938396380900868478770120166215715342197\
                608909161078151052289990510800728152668922674818110091685769535438180101\
                272284674228464477681730626897377329275113284276174651501148470900659340\
                242743273723750048439451011572633079804679262234840092673039434982846094\
                858029986372407321072908691299622598729949143635978471646417649022624531\
                397073137125014042824087134672098489995710684168308927307628311407604212\
                076349078064236904318455562263556357905101239903098363064014511073779845\
                535962321284155214968625564761476760704665742584416074142670680642532429\
                788102464008480218956333029452280039396500686472499958747001119498208082\
                938969533126888218190153781010508393865315931944550539779583198521\",\"1\
                \":\"3865675398591356838870952136584491133843010579866124075525445351141\
                652763109728401214708512174494341133971870785344527055350933335266436592\
                630138529199957862498975596548967827605091359241966757640472295628066598\
                634624767753149952703045124279143641986834574915174302406359887700512368\
                836578487212432025053753746435621209495155905857591256806238672763288068\
                822055144945667186660675503516493390883683601174905326050416080513367359\
                328509080906292978180058396106520856223161824297633630823839676143148322\
                258297729485937587999315811130555054415081750311647067926825291837967862\
                641686975792369641762281336397220440427938025082959848937874477751914970\
                389852234865757264839779101176511083438457506566386743078450230536895330\
                27\",\"2\":\"34678979009750935745049130769101854392262226801733057477302\
                764212173477610313067106720379017820690780291862075790924775230220521966\
                683898569561078039951727810015611769786076379426799679492231251499484103\
                016313431342893052299218257701411134420635411822849180492548798417077596\
                052263781509023220956185868177175424600960897525621837842883751000031697\
                634045822367825926591383155123722022536060767329175072963412023260472370\
                697821184369987671814589826571110103010535930481890038125984986569707388\
                308760855449848021210883201340167250784836745570685822318405074938089768\
                655952675474232562938054985222463354721659466641570890295342127356124009\
                581924467594741476136253115899757482388898366579113613466811149429286382\
                1995825977\",\"3\":\"739997174362328907908776966753217981519568625459645\
                118730188156014983194387368283230104821118376481771498175329300961100220\
                441158362585131937954468301731075929401508434584313121645613734761979728\
                655073318159985275147853061274813421043228895942272514463722301264717456\
                599935415729374863214212997947217957961563969703852757572971041858376691\
                003196128764437287763204694476181350134199105599728244197767784751020137\
                442847062783613738077919435965414081200193602129147090223236096375104392\
                612700580962887424634933996610307305688770088846331154571040920582460567\
                945406606561076110003257155824273464444583437954059391097897624202483515\
                844685248154356738089537819621120634137363514887658796147437535533467659\
                313282364853804763\"},\"mj\":\"13426448386704052122436508368412649282247\
                303006033162699427450001959896440574327789039269069757420462157411177713\
                856967409045887068140889731043689594317098496116863139661748333083\",\"a\
                lpha\":\"749953133907091320110958685876959765910930609093050413081723058\
                056317315492828628059483933389122919792511157869501387845693343782165239\
                244600010908778262519084638845270052505589477731661220834014655616059993\
                674747994891792041079910250595536928642717036255575602156361619791701360\
                492972542402848750066239907355865928596748658135890681040106126592973312\
                538764079253183123087616128187323325192130260663583280545158347836528259\
                823647080793565425864514109518146751201001811445864835585528791581083445\
                824204727279966889171081995979554762898766507618379124177255142503093448\
                155474968310285793608269145001789107256318626544317672446352360574510886\
                784498568566138484268687311129198565677523081021518324805928791495670408\
                127991150930804803713557024911959620666803496981264878420663844500592950\
                75792757040838287433704102735276749598878648075126804052\",\"t\":{\"DELT\
                A\":\"506573473066555526151142771723618701560951598243393504379101312593\
                447957864958977025523610819671733769320439307687793585285837497970192165\
                391894313604193034131792090919169726273587088165377346154380021231914071\
                943076523161037201131295266787291974134944199252836983280332026393853105\
                685672949838578706984381199719308658998850283005812098538066162534933964\
                377927984746078403312513688431588531166439510922152089216951413460196750\
                294613915240810280997848937576194598969745865087007553717308458690046536\
                433693042830163226706200550825314194648704049532453128269605862754012276\
                27865622449941440625470052963648532951276405494\",\"1\":\"72937792414266\
                798627919010984533821294962168592072824850603235208175755599328120857723\
                040658418208609628828754235893185036038712236135375640044146200130169940\
                287497574287294788461580780866969132124658036531132982478316291241342856\
                146575715198298927318848685777807807544218905638719868698072068232339197\
                602560675300139311400605419806853954679685731797622254413493223071187776\
                067198486548711077474048107711913351526406115861241357719287400040760919\
                912637355500374583576772120721097138871195956146877725951474180730204935\
                036073956595672204312877464596555527311880437035191518503555490306724123\
                32693580849873345313218778\",\"0\":\"71253183067442695583226221077523951\
                919090711407142885530534650894885598567752807298177607342068507050674426\
                674474812363886037177691377268529708045447336875444255125927688979995086\
                256783044921168197769385599180448252308989295711405527196918205975272314\
                840512051297581437716330539860660012109600476929235168350796229814376876\
                959934969125832888509758111001469415223679431432630902877566512564196387\
                405704344215498192526841822892698736500645044258247638378598264751850731\
                144258042115061250542280828005791871925552526768015579810490651269513625\
                251848805386919266158511260618794155739857445988659456645387551429011836\
                595004\",\"3\":\"1496614557815269766618683007960982592781357160793947771\
                900821935964831091426339182452547170164592127250159062060293567376554034\
                345203623895132511063663151700025339238809973658093829490653963940668495\
                414718297739574778465406789267528542692113530273661797496407816398968458\
                397065251336730742050999270090015740932883254874516797863620004611158343\
                719809149115236728080474048308441456724313265163803350582694025358723919\
                146624233954786915011633066896362720290380835500990324026001942516839921\
                705777122734913894957686537054586092792866497789939206326821009227612583\
                8236790688870699406293226317562073218766832716996265445665\",\"2\":\"426\
                962399077923059837212880511767336579060172902553844940882371193336375491\
                912990084590291948765051648947337964652748363058471282646092973322139961\
                432989959493435652132064847816253962534476603266201045623702501238201338\
                180468191456293305149666177785865837944911740777964478278799681899260423\
                726962270512325929975515918045697178079417756138843486124881675057309578\
                645714043684648066509420479279338647660646348108797596221367917364155894\
                702787126197772039716243016153861165523722545283219087429171118576589299\
                935958885885889732368830238537596372295927117065243372064465675684796275\
                58862991963775280082685193239235438589\"},\"predicate\":{\"attr_name\":\"\
                age\",\"p_type\":\"GE\",\"value\":18}}]},\"non_revoc_proof\":{\"x_list\"\
                :{\"rho\":\"0058B669E9F98716275992C0586370A2095A0F917F3C461DF0A0D6C78C77\
                2181\",\"r\":\"0A3259FCBD47A5A5AD16D59177231D74BCDC7DFA180EE03885B075BB6\
                60AA18A\",\"r_prime\":\"1457C2429BB6CB24502064329B1FC242EEA991D97519AB0C\
                6C3FD82237738F73\",\"r_prime_prime\":\"00B6D2CE58ECB694985A41DA9B632E335\
                74C751B936AB8F64CF1148A56B38096\",\"r_prime_prime_prime\":\"101449AA1278\
                1A1A9F8A8A0EC43453EF6CB66AF2E3B7AB5C6337BE8D59807135\",\"o\":\"12F51D137\
                7B6937CAF3CA9D485F9B1C86077F7DED0186F3A332F2C3C09603959\",\"o_prime\":\"\
                17D97AC6C9714905B55D18B255AB6943F3A60B23EC90CC8DDA14396DC81576E2\",\"m\"\
                :\"0FAF08677E990AD38781513C0477FEED52B4A1270EFEFE7504BDEAA144E8FFDA\",\"\
                m_prime\":\"093FFB4626868E37738B831D3F37382EB9117E8AC9391EE27557721EAA55\
                03FC\",\"t\":\"19163211BAF5CB68828BC8535B5544D94DCCF0232ABCE0EB73D057758\
                6E20B46\",\"t_prime\":\"1A016081FFD4822B684C44E5E030A08F6075304D200EF9B3\
                FA53F4AFBFA91B90\",\"m2\":\"0F628426135DC0160978C3C74448B5C6B8F80BE76CEA\
                5E7AAA5A29948228AEAA\",\"s\":\"002F34635113AF8A3DD08284FCEE6939663DB1398\
                CD7CF3C62421335AD1A9A50\",\"c\":\"00804101C1314BD5F7832334F492B1D3F6401D\
                EE03E23AF9E5DAF3FA411F7863\"},\"c_list\":{\"e\":\"6 4DA79BD9221A350F21E0\
                C0C467444060A40148EABEAD61858ED1F51CCD98A819 4 1CDA1926F30C2196B84F72FEC\
                DFD8FA8FE0732D8EFD7E531188CA065E45CDF98 4 1F2A258455FB4E437062B0D3C129E9\
                5FDF0DC97B568CCAA13511EA914E286393\",\"d\":\"6 439257FC8158E42997EF0D484\
                DCBE18DB87E061AFA5D67C30E948A840EF6D8A7 4 33DD91EA04ED0A707096F2DB32DECF\
                9CCBE9A44C1705C3FB579A73E436CE7544 4 24A5B0D11F7D0903273946CF7B2160F3B84\
                17699226768062B1BA9F70F3577B4\",\"a\":\"6 42DB6F3CFC93EA5502BF7990D6F6E2\
                9B685DFBC8AA28BF9B49494ADB15D41D53 4 142AF9839ECA75219F6C1EF5EB0D527EEAC\
                43BA314CC31FFF77B31CDDE8DFB5E 4 12F1CD3F4E587C3827E9B964F404C157506B0E55\
                2C87EF24FD5D60F05542C4AC\",\"g\":\"6 4962639E54487BEB835467FCCF9D2B8E0B4\
                0DB6640356C33407688C2F3348B90 4 3648BA30ABCCA108125E7EA8E05CB06566422010\
                45630D74423D7D66B7CBE5EB 4 2E4EE73D618C8C47D657588481E5790C4CA62E1CC3470\
                472E306B2DBBD63DA1B\",\"w\":\"21 1186EF5CC28431D1DAF117363EF2CD0715B48E3\
                AE8B2C2576CA4B4CC5B341AB19 21 13BFC393544CFA9D75E05ECE79A52DCCFB796D8B34\
                F5E939D3FDD14FD791CCC6E 6 5E6E81984909EE873EE0E77C31DFD0A09043DA6AA5851A\
                739344A7F0FC308FF5 4 13401B92EBFEBB63FF2EB96E215A114E3C0981BB381ECAF7DE8\
                ADE8ABD0D7F4A 6 6B58F4A4B9AF9A58BFF1B247D2F13311EA1832A65EC49D7C51361F3F\
                6199AF78 4 3F4C23133568F545A9085D6710F5A6A60120218D240A53C2A23DE804B2662\
                603\",\"s\":\"21 144F652F816066DCE6C46B6FB017B61D31342F485FE1847AB663252\
                3BE3DF3AF0 21 131E691D944F1C415B041C98DE978A29B175867D57F3383BDA5E39F575\
                DCE9CEB 6 72A7B4BC12AC64556B61131116B35999608A3117D9747F93DDAA5A80F4E424\
                FA 4 2D26D2CDED23F3EB7F66885D652FE25CB278B2CDA35EF368DFA3AFDF8B118A9B 6 \
                4BC7C3771DAE4E83A01688E0E2CDC0278CB7879E11D76F6E357CB436852C2550 4 31F6F\
                27AED9CBA0CC5D8A93363BC15C10A3E4302E249D6C0615FF09A7DE225F8\",\"u\":\"21 \
                146CF05233D7CA1FBCE9E9552EF4C194AF752A9852D54758924309DA80F2BBDBD 21 13\
                020398FE0E6BB9C2A640E4CB3DAB224E0D633AA3D79169BC81F34A616D91C45 6 609D8A\
                0A9F25326F87CFE5168E7FAD19BC442C4C3EBB66F5424AFBCD8F531B04 4 2E649292BD9\
                801B61C719714D55B55B65CC5EB69DB5C37B59317695B4162F5E9 6 7C0D14A80113993D\
                1761D96B61E77C8B55C1E0DFD460CA167523C6F2FCEA4F0F 4 11A64C18C67E0940939EC\
                47B25CCC08112D6B1B1731C244F2A8D7D33966C39EE\"}}}],\"aggregated_proof\":{\
                \"c_hash\":\"22787145290445437506126833717127058795675575081098668841671\
                239083870394860347\",\"c_list\":[[4,21,218,115,245,146,212,101,124,193,2\
                34,223,6,186,195,40,8,160,180,95,225,37,25,208,98,150,64,91,193,178,36,3\
                0,202,32,21,152,172,102,27,100,186,202,141,230,87,201,137,146,81,234,60,\
                168,27,81,203,149,166,234,126,51,146,81,0,1,3,0,0,0,0,0,0,0,0,0,0,0,0,0,\
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,\
                0,0,0,0,0,0,0,0,0,0,0,0,0,0],[4,11,140,168,70,166,144,230,162,25,162,197\
                ,1,98,250,57,90,250,21,119,98,235,125,38,59,148,195,145,136,255,23,244,2\
                06,0,204,215,172,214,174,39,249,56,196,151,125,98,85,177,3,16,252,217,18\
                4,179,183,79,212,29,128,118,74,216,161,92,209,0,0,0,0,0,0,0,0,0,0,0,0,0,\
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,\
                0,0,0,0,0,0,0,0,0,0,0,0,0,0],[4,12,153,5,179,180,130,72,106,155,150,180,\
                145,249,253,196,119,254,26,53,4,71,242,201,232,55,208,240,56,46,216,72,1\
                68,30,143,252,225,193,167,185,9,142,122,45,9,141,179,134,226,142,135,11,\
                250,31,71,32,30,140,9,18,92,30,41,117,57,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0\
                ,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0\
                ,0,0,0,0,0,0,0,0,0,0,0],[4,26,50,189,90,170,147,216,108,31,39,190,249,19\
                3,230,154,251,92,94,156,142,78,67,155,36,24,89,253,243,106,104,166,48,13\
                ,70,165,179,232,40,231,70,213,128,13,249,178,53,14,131,0,101,165,50,161,\
                187,127,206,82,147,181,93,204,174,245,165,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,\
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,\
                0,0,0,0,0,0,0,0,0,0,0,0],[11,212,78,158,29,169,131,14,36,131,34,132,90,8\
                9,25,19,75,128,186,245,169,43,205,41,180,85,111,186,235,4,166,168,11,228\
                ,149,17,19,133,48,187,214,180,159,153,200,21,163,175,176,183,91,22,76,22\
                3,159,251,48,175,44,19,73,130,192,134,18,137,243,62,206,84,55,81,59,46,2\
                28,164,138,224,5,214,84,46,39,10,59,211,102,54,25,119,189,14,239,106,184\
                ,155,3,149,185,129,16,220,6,104,72,196,116,165,234,52,151,208,23,97,78,7\
                3,226,71,118,157,142,21,120,123,130,223,212,62],[3,14,74,95,243,0,221,11\
                ,217,139,248,108,31,209,118,240,192,129,226,213,109,155,135,236,58,22,79\
                ,67,142,215,33,40,15,202,128,177,209,7,242,147,35,9,149,12,20,224,89,178\
                ,35,203,144,13,242,174,178,30,212,233,42,228,35,105,136,64,6,10,32,222,1\
                26,169,63,21,218,240,249,253,219,232,65,89,248,118,119,44,90,223,19,93,2\
                34,165,82,26,200,41,195,54,28,82,167,122,153,185,119,76,132,150,172,174,\
                46,8,205,142,37,114,154,237,123,151,87,65,149,206,176,133,150,53,155,105\
                ],[6,202,54,105,189,187,234,228,172,110,60,80,147,38,108,124,87,51,46,20\
                9,181,77,144,234,233,234,215,39,213,63,203,239,4,53,142,72,36,5,86,119,4\
                5,202,69,34,164,196,213,126,29,206,100,29,95,73,164,175,67,237,213,213,2\
                15,177,229,22,22,17,214,222,148,185,148,52,231,211,185,31,88,120,83,127,\
                125,225,234,111,44,81,18,113,7,38,200,126,246,149,8,67,4,17,217,25,137,8\
                5,204,170,61,45,143,22,120,191,196,26,158,208,18,30,149,30,35,66,106,86,\
                234,128,80,228,129,47],[224,155,175,116,62,234,207,133,155,74,3,88,149,8\
                3,154,67,61,188,148,171,246,173,183,214,79,16,178,224,148,217,161,123,11\
                1,50,138,108,129,111,164,176,75,201,67,29,170,35,211,197,33,122,36,2,117\
                ,90,225,96,67,202,195,231,17,120,236,207,252,131,77,229,133,242,85,190,2\
                20,158,253,52,199,93,52,89,24,71,35,175,110,169,221,244,204,90,80,179,13\
                3,80,103,85,223,11,101,247,82,167,96,20,13,247,14,144,67,245,250,231,191\
                ,187,121,7,196,34,137,178,9,241,220,207,206,163,175,125,87,42,49,220,108\
                ,235,179,234,160,17,127,202,127,199,43,143,231,37,9,142,3,159,56,81,71,8\
                6,184,67,175,207,76,135,105,244,249,124,35,191,191,225,87,91,232,14,217,\
                29,203,12,23,118,73,73,70,171,225,55,238,58,131,36,110,64,0,76,89,200,36\
                ,51,23,54,175,101,59,151,111,228,49,152,75,245,232,43,121,254,194,66,114\
                ,40,250,20,26,107,153,109,61,170,146,115,204,60,141,88,77,200,243,252,90\
                ,76,240,84,190,252,251,238,52,81,170,169,248,200,67,11,184,243,135,57,23\
                8,15],[2,52,111,22,72,252,158,194,114,107,154,49,238,249,243,146,161,88,\
                64,6,129,147,230,27,18,92,166,225,230,111,189,193,113,198,6,108,204,174,\
                228,155,77,75,165,54,139,241,79,123,110,48,190,47,232,99,12,160,56,95,24\
                1,143,177,209,26,6,142,33,174,163,134,141,162,135,231,40,43,251,155,61,1\
                04,181,145,43,68,105,41,185,194,140,231,187,158,231,92,139,133,226,102,1\
                33,185,152,211,23,9,2,28,169,139,96,112,36,81,79,132,133,109,75,103,43,2\
                17,144,196,181,4,193,255,68,201,162,169,233,11,52,41,149,133,137,224,105\
                ,201,118,213,125,41,12,93,74,162,187,177,57,120,4,153,52,45,64,128,155,6\
                ,247,22,105,246,192,51,186,247,191,68,27,106,111,169,4,172,35,185,109,72\
                ,236,216,130,203,69,16,129,244,215,40,65,63,115,173,202,95,158,141,116,1\
                94,105,108,28,45,233,160,87,197,108,182,49,132,109,188,253,124,194,83,24\
                2,88,109,93,50,203,252,197,55,154,211,197,127,193,134,6,3,159,17,222,229\
                ,100,134,113,168,162,66,202,147,55,184,237,141,66,43,116,182,169,107,60]\
                ,[57,199,33,230,147,123,117,233,98,234,233,201,3,210,47,2,40,100,14,37,1\
                93,85,56,233,220,70,159,40,17,82,68,65,86,6,226,47,38,86,57,22,150,37,14\
                0,122,167,118,86,81,246,59,74,79,141,151,90,219,160,10,68,35,78,249,216,\
                126,63,134,243,108,240,227,126,98,17,113,28,56,105,195,119,134,17,190,14\
                2,137,36,73,197,74,127,199,44,56,143,192,80,108,77,161,27,227,133,10,110\
                ,154,116,99,169,196,243,105,220,235,137,57,55,217,70,156,228,159,26,220,\
                124,122,13,117,136,155,139,243,43,206,212,201,253,132,67,117,31,179,84,2\
                5,122,113,197,88,49,120,70,233,106,221,27,76,252,217,63,9,24,5,92,17,21,\
                16,157,106,105,103,245,114,240,251,150,149,24,175,255,253,46,215,230,66,\
                72,58,175,62,71,105,44,105,162,247,228,94,192,46,104,205,202,144,93,137,\
                11,228,231,158,192,207,47,14,219,78,236,17,97,105,67,208,74,46,74,129,18\
                7,190,124,185,170,165,237,127,117,141,90,140,61,201,55,56,131,214,70,214\
                ,134,31,34,31,206,67,24,107,132,15,21,39,160,218],[1,82,56,40,152,224,13\
                4,178,100,4,207,24,183,85,0,79,123,186,147,1,57,176,97,235,88,234,183,11\
                2,149,169,227,68,133,146,160,100,171,164,138,50,175,21,102,103,223,91,23\
                ,248,232,92,144,151,16,91,146,129,130,26,73,100,229,141,194,52,213,148,2\
                49,28,183,97,60,213,55,153,226,165,176,22,124,27,140,58,18,210,41,252,33\
                ,196,111,135,3,166,92,59,29,48,68,25,10,136,89,71,177,5,90,94,85,171,184\
                ,167,142,112,97,75,222,237,123,56,146,157,80,226,16,82,79,111,231,123,21\
                5,45,55,51,38,186,170,170,1,40,4,228,31,145,226,225,8,185,166,124,193,33\
                ,46,79,144,59,232,229,191,3,174,167,192,165,111,144,11,35,138,250,64,8,7\
                6,23,251,2,5,109,55,119,173,71,76,14,154,48,202,98,45,212,105,114,85,184\
                ,107,74,22,55,220,249,240,212,253,145,254,0,105,91,187,222,39,114,86,217\
                ,170,246,96,16,53,169,246,49,107,129,209,62,221,11,151,116,122,204,152,3\
                5,153,96,76,18,249,32,216,72,17,102,225,68,27,123,25,4,243,32,92,95,238,\
                231,40,167,253],[118,142,1,113,199,202,65,246,144,63,225,3,201,248,229,2\
                41,139,140,126,90,150,157,0,188,197,13,154,214,200,170,164,210,45,50,24,\
                191,121,90,9,77,179,153,218,247,24,160,229,135,99,240,84,111,118,214,223\
                ,131,9,58,175,213,143,38,165,153,59,167,224,158,235,218,203,225,105,0,21\
                ,176,101,25,66,11,134,67,214,130,197,226,192,177,84,247,229,110,180,174,\
                14,44,63,78,136,129,73,27,2,176,51,96,198,56,185,16,215,55,246,175,14,20\
                6,56,103,175,79,240,213,113,135,2,121,153,184,227,69,32,161,20,142,36,25\
                2,107,254,135,169,206,138,193,65,101,97,156,187,33,216,182,111,172,135,2\
                27,185,141,251,159,199,87,151,44,125,169,234,219,68,27,197,230,87,113,93\
                ,201,97,243,37,96,232,27,113,228,95,127,24,238,183,92,230,99,4,252,28,14\
                5,4,101,159,74,163,236,221,139,151,188,51,94,136,228,211,120,3,149,47,20\
                7,54,186,104,52,131,152,167,187,49,202,89,0,42,34,85,25,77,64,131,199,25\
                0,139,131,0,204,35,54,109,163,127,104,217,143,178,95,135,110,35,77,9,33]\
                ,[1,145,72,146,167,130,217,80,155,140,130,41,240,57,251,8,190,118,165,38\
                ,37,143,124,197,152,255,75,108,24,220,101,4,31,139,206,29,249,199,84,41,\
                38,129,13,132,17,210,187,29,225,224,114,139,18,15,57,97,157,208,190,193,\
                118,175,137,243,76,21,230,72,51,99,232,18,242,233,52,52,65,172,66,170,24\
                1,123,172,66,43,117,221,113,12,198,44,8,245,139,125,228,3,113,70,183,107\
                ,101,25,105,11,33,20,137,245,240,6,219,150,166,116,213,57,129,60,43,92,9\
                3,116,122,47,5,145,249,252,190,9,76,172,183,6,195,248,103,219,43,12,15,1\
                30,40,124,184,38,212,76,162,205,43,157,211,106,190,174,149,34,232,184,28\
                ,182,120,216,110,86,57,116,79,254,128,27,109,112,136,184,241,113,253,139\
                ,117,106,160,150,104,47,25,118,128,88,153,241,198,170,50,43,136,89,215,2\
                6,80,100,221,239,167,103,2,212,52,41,48,59,55,7,48,134,149,197,109,75,48\
                ,36,198,44,147,231,235,48,167,253,186,209,211,62,96,242,96,11,233,113,55\
                ,31,150,1,117,198,125,110,234,94,232,176,93,163,66,246]]}}",
            )
            .unwrap();

            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 13. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(!proof_verifier.verify(&proof, &nonce).unwrap());
            proof_verifier.accept_legacy_revocation(true);
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_multiple_credentials_used_for_proof() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();

            let gvt_credential_values = helpers::gvt_credential_values();

            // 2. Issuer creates and signs GVT credential for Prover
            let gvt_credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (
                gvt_credential_pub_key,
                gvt_credential_priv_key,
                gvt_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, false)
                .unwrap();

            let gvt_credential_nonce = new_nonce().unwrap();

            let gvt_blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                gvt_blinded_credential_secrets,
                gvt_credential_secrets_blinding_factors,
                gvt_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &gvt_credential_key_correctness_proof,
                &gvt_blind_credential_values,
                &gvt_credential_nonce,
            )
            .unwrap();

            let gvt_credential_issuance_nonce = new_nonce().unwrap();

            let (mut gvt_credential_signature, gvt_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &gvt_blinded_credential_secrets,
                    &gvt_blinded_credential_secrets_correctness_proof,
                    &gvt_credential_nonce,
                    &gvt_credential_issuance_nonce,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    &gvt_credential_priv_key,
                )
                .unwrap();

            // 3. Prover processes GVT credential
            Prover::process_credential_signature(
                &mut gvt_credential_signature,
                &gvt_credential_values
                    .merge(&gvt_blind_credential_values)
                    .unwrap(),
                &gvt_signature_correctness_proof,
                &gvt_credential_secrets_blinding_factors,
                &gvt_credential_pub_key,
                &gvt_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 4. Issuer creates and signs XYZ credential for Prover
            let xyz_credential_schema = helpers::xyz_credential_schema();
            let (
                xyz_credential_pub_key,
                xyz_credential_priv_key,
                xyz_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&xyz_credential_schema, &non_credential_schema, false)
                .unwrap();

            let xyz_credential_nonce = new_nonce().unwrap();
            let xyz_credential_values = helpers::xyz_credential_values();

            let xyz_blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                xyz_blinded_credential_secrets,
                xyz_credential_secrets_blinding_factors,
                xyz_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &xyz_credential_pub_key,
                &xyz_credential_key_correctness_proof,
                &xyz_blind_credential_values,
                &xyz_credential_nonce,
            )
            .unwrap();

            let xyz_credential_issuance_nonce = new_nonce().unwrap();

            let (mut xyz_credential_signature, xyz_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &xyz_blinded_credential_secrets,
                    &xyz_blinded_credential_secrets_correctness_proof,
                    &xyz_credential_nonce,
                    &xyz_credential_issuance_nonce,
                    &xyz_credential_values,
                    &xyz_credential_pub_key,
                    &xyz_credential_priv_key,
                )
                .unwrap();

            // 5. Prover processes XYZ credential
            Prover::process_credential_signature(
                &mut xyz_credential_signature,
                &xyz_credential_values
                    .merge(&xyz_blind_credential_values)
                    .unwrap(),
                &xyz_signature_correctness_proof,
                &xyz_credential_secrets_blinding_factors,
                &xyz_credential_pub_key,
                &xyz_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();
            // 6. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 7. Verifier creates proof request which contains two sub proof requests: GVT and XYZ
            let gvt_sub_proof_request = helpers::gvt_sub_proof_request();
            let xyz_sub_proof_request = helpers::xyz_sub_proof_request();

            // 8. Prover creates proof builder
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();

            // 9. Prover adds GVT sub proof request
            proof_builder
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_signature,
                    &gvt_credential_values
                        .merge(&gvt_blind_credential_values)
                        .unwrap(),
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 10. Prover adds XYZ sub proof request
            proof_builder
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_signature,
                    &xyz_credential_values
                        .merge(&xyz_blind_credential_values)
                        .unwrap(),
                    &xyz_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 11. Prover gets proof which contains sub proofs for GVT and XYZ sub proof requests
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof for GVT and XYZ sub proof requests
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_multiple_credentials_different_link_secret() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();

            let gvt_credential_values = helpers::gvt_credential_values();

            // 2. Issuer creates and signs GVT credential for Prover
            let gvt_credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (
                gvt_credential_pub_key,
                gvt_credential_priv_key,
                gvt_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, false)
                .unwrap();

            let gvt_credential_nonce = new_nonce().unwrap();

            let gvt_blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                gvt_blinded_credential_secrets,
                gvt_credential_secrets_blinding_factors,
                gvt_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &gvt_credential_key_correctness_proof,
                &gvt_blind_credential_values,
                &gvt_credential_nonce,
            )
            .unwrap();

            let gvt_credential_issuance_nonce = new_nonce().unwrap();

            let (mut gvt_credential_signature, gvt_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &gvt_blinded_credential_secrets,
                    &gvt_blinded_credential_secrets_correctness_proof,
                    &gvt_credential_nonce,
                    &gvt_credential_issuance_nonce,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    &gvt_credential_priv_key,
                )
                .unwrap();

            // 3. Prover processes GVT credential
            Prover::process_credential_signature(
                &mut gvt_credential_signature,
                &gvt_credential_values
                    .merge(&gvt_blind_credential_values)
                    .unwrap(),
                &gvt_signature_correctness_proof,
                &gvt_credential_secrets_blinding_factors,
                &gvt_credential_pub_key,
                &gvt_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 4. Issuer creates and signs PQR credential for Prover
            let pqr_credential_schema = helpers::pqr_credential_schema();
            let (
                pqr_credential_pub_key,
                pqr_credential_priv_key,
                pqr_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&pqr_credential_schema, &non_credential_schema, false)
                .unwrap();

            // The second credential has a different link secret
            let link_secret_1 = Prover::new_link_secret().unwrap();

            let pqr_credential_nonce = new_nonce().unwrap();
            let pqr_credential_values = helpers::pqr_credential_values();

            let pqr_blind_credential_values = helpers::blind_credential_values(&link_secret_1);
            let (
                pqr_blinded_credential_secrets,
                pqr_credential_secrets_blinding_factors,
                pqr_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &pqr_credential_pub_key,
                &pqr_credential_key_correctness_proof,
                &pqr_blind_credential_values,
                &pqr_credential_nonce,
            )
            .unwrap();

            let pqr_credential_issuance_nonce = new_nonce().unwrap();

            let (mut pqr_credential_signature, pqr_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &pqr_blinded_credential_secrets,
                    &pqr_blinded_credential_secrets_correctness_proof,
                    &pqr_credential_nonce,
                    &pqr_credential_issuance_nonce,
                    &pqr_credential_values,
                    &pqr_credential_pub_key,
                    &pqr_credential_priv_key,
                )
                .unwrap();

            // 5. Prover processes XYZ credential
            Prover::process_credential_signature(
                &mut pqr_credential_signature,
                &pqr_credential_values
                    .merge(&pqr_blind_credential_values)
                    .unwrap(),
                &pqr_signature_correctness_proof,
                &pqr_credential_secrets_blinding_factors,
                &pqr_credential_pub_key,
                &pqr_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();
            // 6. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 7. Verifier creates proof request which contains two sub proof requests: GVT and XYZ
            let gvt_sub_proof_request = helpers::gvt_sub_proof_request_1();
            let pqr_sub_proof_request = helpers::pqr_sub_proof_request();

            // 8. Prover creates proof builder
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();

            // 9. Prover adds GVT sub proof request
            proof_builder
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_signature,
                    &gvt_credential_values
                        .merge(&gvt_blind_credential_values)
                        .unwrap(),
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 10. Prover adds XYZ sub proof request
            proof_builder
                .add_sub_proof_request(
                    &pqr_sub_proof_request,
                    &pqr_credential_schema,
                    &non_credential_schema,
                    &pqr_credential_signature,
                    &pqr_credential_values
                        .merge(&pqr_blind_credential_values)
                        .unwrap(),
                    &pqr_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 11. Prover gets proof which contains sub proofs for GVT and XYZ sub proof requests
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof for GVT and PQR sub proof requests
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            // Verifier expects link secret (named `master_secret` here) to be same in both credentials
            proof_verifier.add_common_attribute(LINK_SECRET).unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &pqr_sub_proof_request,
                    &pqr_credential_schema,
                    &non_credential_schema,
                    &pqr_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // The proof will fail since value of `master_secret` is different in both credentials
            assert_eq!(
                ErrorKind::ProofRejected,
                proof_verifier.verify(&proof, &nonce).unwrap_err().kind()
            );
        }

        #[test]
        fn anoncreds_works_for_multiple_credentials_common_attribute_same_value() {
            // 2 credentials have attribute with same name and same value and the proof proves that values are same.
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();

            let gvt_credential_values = helpers::gvt_credential_values();

            // 2. Issuer creates and signs GVT credential for Prover
            let gvt_credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (
                gvt_credential_pub_key,
                gvt_credential_priv_key,
                gvt_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, false)
                .unwrap();

            let gvt_credential_nonce = new_nonce().unwrap();

            let gvt_blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                gvt_blinded_credential_secrets,
                gvt_credential_secrets_blinding_factors,
                gvt_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &gvt_credential_key_correctness_proof,
                &gvt_blind_credential_values,
                &gvt_credential_nonce,
            )
            .unwrap();

            let gvt_credential_issuance_nonce = new_nonce().unwrap();

            let (mut gvt_credential_signature, gvt_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &gvt_blinded_credential_secrets,
                    &gvt_blinded_credential_secrets_correctness_proof,
                    &gvt_credential_nonce,
                    &gvt_credential_issuance_nonce,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    &gvt_credential_priv_key,
                )
                .unwrap();

            // 3. Prover processes GVT credential
            Prover::process_credential_signature(
                &mut gvt_credential_signature,
                &gvt_credential_values
                    .merge(&gvt_blind_credential_values)
                    .unwrap(),
                &gvt_signature_correctness_proof,
                &gvt_credential_secrets_blinding_factors,
                &gvt_credential_pub_key,
                &gvt_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 4. Issuer creates and signs PQR credential for Prover
            let pqr_credential_schema = helpers::pqr_credential_schema();
            let (
                pqr_credential_pub_key,
                pqr_credential_priv_key,
                pqr_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&pqr_credential_schema, &non_credential_schema, false)
                .unwrap();

            let pqr_credential_nonce = new_nonce().unwrap();
            // PQR credential has same value for attribute name as the GVT credential
            let pqr_credential_values = helpers::pqr_credential_values();

            let pqr_blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                pqr_blinded_credential_secrets,
                pqr_credential_secrets_blinding_factors,
                pqr_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &pqr_credential_pub_key,
                &pqr_credential_key_correctness_proof,
                &pqr_blind_credential_values,
                &pqr_credential_nonce,
            )
            .unwrap();

            let pqr_credential_issuance_nonce = new_nonce().unwrap();

            let (mut pqr_credential_signature, pqr_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &pqr_blinded_credential_secrets,
                    &pqr_blinded_credential_secrets_correctness_proof,
                    &pqr_credential_nonce,
                    &pqr_credential_issuance_nonce,
                    &pqr_credential_values,
                    &pqr_credential_pub_key,
                    &pqr_credential_priv_key,
                )
                .unwrap();

            // 5. Prover processes XYZ credential
            Prover::process_credential_signature(
                &mut pqr_credential_signature,
                &pqr_credential_values
                    .merge(&pqr_blind_credential_values)
                    .unwrap(),
                &pqr_signature_correctness_proof,
                &pqr_credential_secrets_blinding_factors,
                &pqr_credential_pub_key,
                &pqr_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();
            // 6. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 7. Verifier creates proof request which contains two sub proof requests: GVT and XYZ
            let gvt_sub_proof_request = helpers::gvt_sub_proof_request_1();
            let pqr_sub_proof_request = helpers::pqr_sub_proof_request();

            // 8. Prover creates proof builder
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();
            // name attribute value is same across both gvt and pqr credentials
            proof_builder.add_common_attribute("name").unwrap();

            // 9. Prover adds GVT sub proof request
            proof_builder
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_signature,
                    &gvt_credential_values
                        .merge(&gvt_blind_credential_values)
                        .unwrap(),
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 10. Prover adds XYZ sub proof request
            proof_builder
                .add_sub_proof_request(
                    &pqr_sub_proof_request,
                    &pqr_credential_schema,
                    &non_credential_schema,
                    &pqr_credential_signature,
                    &pqr_credential_values
                        .merge(&pqr_blind_credential_values)
                        .unwrap(),
                    &pqr_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 11. Prover gets proof which contains sub proofs for GVT and XYZ sub proof requests
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof for GVT and PQR sub proof requests
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            // Verifier expects link secret (named `master_secret` here) to be same in both credentials
            proof_verifier.add_common_attribute(LINK_SECRET).unwrap();
            // Verifier expects attribute `name` to be same in both credentials
            proof_verifier.add_common_attribute("name").unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &pqr_sub_proof_request,
                    &pqr_credential_schema,
                    &non_credential_schema,
                    &pqr_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_multiple_credentials_common_attribute_different_value() {
            // 2 credentials have attribute with same name but different values and the proof fails to prove that they have same value.
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();

            let gvt_credential_values = helpers::gvt_credential_values();

            // 2. Issuer creates and signs GVT credential for Prover
            let gvt_credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (
                gvt_credential_pub_key,
                gvt_credential_priv_key,
                gvt_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, false)
                .unwrap();

            let gvt_credential_nonce = new_nonce().unwrap();

            let gvt_blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                gvt_blinded_credential_secrets,
                gvt_credential_secrets_blinding_factors,
                gvt_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &gvt_credential_key_correctness_proof,
                &gvt_blind_credential_values,
                &gvt_credential_nonce,
            )
            .unwrap();

            let gvt_credential_issuance_nonce = new_nonce().unwrap();

            let (mut gvt_credential_signature, gvt_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &gvt_blinded_credential_secrets,
                    &gvt_blinded_credential_secrets_correctness_proof,
                    &gvt_credential_nonce,
                    &gvt_credential_issuance_nonce,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    &gvt_credential_priv_key,
                )
                .unwrap();

            // 3. Prover processes GVT credential
            Prover::process_credential_signature(
                &mut gvt_credential_signature,
                &gvt_credential_values
                    .merge(&gvt_blind_credential_values)
                    .unwrap(),
                &gvt_signature_correctness_proof,
                &gvt_credential_secrets_blinding_factors,
                &gvt_credential_pub_key,
                &gvt_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 4. Issuer creates and signs PQR credential for Prover
            let pqr_credential_schema = helpers::pqr_credential_schema();
            let (
                pqr_credential_pub_key,
                pqr_credential_priv_key,
                pqr_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&pqr_credential_schema, &non_credential_schema, false)
                .unwrap();

            let pqr_credential_nonce = new_nonce().unwrap();
            let pqr_credential_values = helpers::pqr_credential_values_1();

            let pqr_blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                pqr_blinded_credential_secrets,
                pqr_credential_secrets_blinding_factors,
                pqr_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &pqr_credential_pub_key,
                &pqr_credential_key_correctness_proof,
                &pqr_blind_credential_values,
                &pqr_credential_nonce,
            )
            .unwrap();

            let pqr_credential_issuance_nonce = new_nonce().unwrap();

            let (mut pqr_credential_signature, pqr_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &pqr_blinded_credential_secrets,
                    &pqr_blinded_credential_secrets_correctness_proof,
                    &pqr_credential_nonce,
                    &pqr_credential_issuance_nonce,
                    &pqr_credential_values,
                    &pqr_credential_pub_key,
                    &pqr_credential_priv_key,
                )
                .unwrap();

            // 5. Prover processes XYZ credential
            Prover::process_credential_signature(
                &mut pqr_credential_signature,
                &pqr_credential_values
                    .merge(&pqr_blind_credential_values)
                    .unwrap(),
                &pqr_signature_correctness_proof,
                &pqr_credential_secrets_blinding_factors,
                &pqr_credential_pub_key,
                &pqr_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();
            // 6. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 7. Verifier creates proof request which contains two sub proof requests: GVT and XYZ
            let gvt_sub_proof_request = helpers::gvt_sub_proof_request_1();
            let pqr_sub_proof_request = helpers::pqr_sub_proof_request();

            // 8. Prover creates proof builder
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();
            // name attribute value is different in both gvt and pqr credentials
            proof_builder.add_common_attribute("name").unwrap();

            // 9. Prover adds GVT sub proof request
            proof_builder
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_signature,
                    &gvt_credential_values
                        .merge(&gvt_blind_credential_values)
                        .unwrap(),
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 10. Prover adds XYZ sub proof request
            proof_builder
                .add_sub_proof_request(
                    &pqr_sub_proof_request,
                    &pqr_credential_schema,
                    &non_credential_schema,
                    &pqr_credential_signature,
                    &pqr_credential_values
                        .merge(&pqr_blind_credential_values)
                        .unwrap(),
                    &pqr_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 11. Prover gets proof which contains sub proofs for GVT and XYZ sub proof requests
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof for GVT and XYZ sub proof requests
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            // Verifier expects link secret (named `master_secret` here) to be same in both credentials
            proof_verifier.add_common_attribute(LINK_SECRET).unwrap();
            // Verifier expects attribute `name` to be same in both credentials
            proof_verifier.add_common_attribute("name").unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &pqr_sub_proof_request,
                    &pqr_credential_schema,
                    &non_credential_schema,
                    &pqr_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // The proof will fail since value of `name` is different in both credentials
            assert_eq!(
                ErrorKind::ProofRejected,
                proof_verifier.verify(&proof, &nonce).unwrap_err().kind()
            );
        }

        #[test]
        fn anoncreds_works_for_multiple_credentials_missing_common_attribute() {
            // 2 credentials are used to create a proof that they both have a certain attribute with same name and value but that is not the case.
            // The proof verification fails.

            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();

            let gvt_credential_values = helpers::gvt_credential_values();

            // 2. Issuer creates and signs GVT credential for Prover
            let gvt_credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (
                gvt_credential_pub_key,
                gvt_credential_priv_key,
                gvt_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, false)
                .unwrap();

            let gvt_credential_nonce = new_nonce().unwrap();

            let gvt_blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                gvt_blinded_credential_secrets,
                gvt_credential_secrets_blinding_factors,
                gvt_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &gvt_credential_key_correctness_proof,
                &gvt_blind_credential_values,
                &gvt_credential_nonce,
            )
            .unwrap();

            let gvt_credential_issuance_nonce = new_nonce().unwrap();

            let (mut gvt_credential_signature, gvt_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &gvt_blinded_credential_secrets,
                    &gvt_blinded_credential_secrets_correctness_proof,
                    &gvt_credential_nonce,
                    &gvt_credential_issuance_nonce,
                    &gvt_credential_values,
                    &gvt_credential_pub_key,
                    &gvt_credential_priv_key,
                )
                .unwrap();

            // 3. Prover processes GVT credential
            Prover::process_credential_signature(
                &mut gvt_credential_signature,
                &gvt_credential_values
                    .merge(&gvt_blind_credential_values)
                    .unwrap(),
                &gvt_signature_correctness_proof,
                &gvt_credential_secrets_blinding_factors,
                &gvt_credential_pub_key,
                &gvt_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 4. Issuer creates and signs XYZ credential for Prover
            let xyz_credential_schema = helpers::xyz_credential_schema();
            let (
                xyz_credential_pub_key,
                xyz_credential_priv_key,
                xyz_credential_key_correctness_proof,
            ) = Issuer::new_credential_def(&xyz_credential_schema, &non_credential_schema, false)
                .unwrap();

            let xyz_credential_nonce = new_nonce().unwrap();
            let xyz_credential_values = helpers::xyz_credential_values();

            let xyz_blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                xyz_blinded_credential_secrets,
                xyz_credential_secrets_blinding_factors,
                xyz_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &xyz_credential_pub_key,
                &xyz_credential_key_correctness_proof,
                &xyz_blind_credential_values,
                &xyz_credential_nonce,
            )
            .unwrap();

            let xyz_credential_issuance_nonce = new_nonce().unwrap();

            let (mut xyz_credential_signature, xyz_signature_correctness_proof) =
                Issuer::sign_credential(
                    PROVER_ID,
                    &xyz_blinded_credential_secrets,
                    &xyz_blinded_credential_secrets_correctness_proof,
                    &xyz_credential_nonce,
                    &xyz_credential_issuance_nonce,
                    &xyz_credential_values,
                    &xyz_credential_pub_key,
                    &xyz_credential_priv_key,
                )
                .unwrap();

            // 5. Prover processes XYZ credential
            Prover::process_credential_signature(
                &mut xyz_credential_signature,
                &xyz_credential_values
                    .merge(&xyz_blind_credential_values)
                    .unwrap(),
                &xyz_signature_correctness_proof,
                &xyz_credential_secrets_blinding_factors,
                &xyz_credential_pub_key,
                &xyz_credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();
            // 6. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 7. Verifier creates proof request which contains two sub proof requests: GVT and XYZ
            let gvt_sub_proof_request = helpers::gvt_sub_proof_request();
            let xyz_sub_proof_request = helpers::xyz_sub_proof_request();

            // 8. Prover creates proof builder
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute(LINK_SECRET).unwrap();

            // 9. Prover adds GVT sub proof request
            proof_builder
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_signature,
                    &gvt_credential_values
                        .merge(&gvt_blind_credential_values)
                        .unwrap(),
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 10. Prover adds XYZ sub proof request
            proof_builder
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_signature,
                    &xyz_credential_values
                        .merge(&xyz_blind_credential_values)
                        .unwrap(),
                    &xyz_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // 11. Prover gets proof which contains sub proofs for GVT and XYZ sub proof requests
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof for GVT and XYZ sub proof requests
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            // Verifier expects link secret (named `master_secret` here) to be same in both credentials
            proof_verifier.add_common_attribute(LINK_SECRET).unwrap();
            // Verifier expects attribute `name` to be same in both credentials
            proof_verifier.add_common_attribute("name").unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &gvt_sub_proof_request,
                    &gvt_credential_schema,
                    &non_credential_schema,
                    &gvt_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            // The proof will fail since `name` is not present in XYZ credential
            assert_eq!(
                ErrorKind::ProofRejected,
                proof_verifier.verify(&proof, &nonce).unwrap_err().kind()
            );
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_for_three_credentials_proving_first() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Issuer issues first credential
            let link_secret_1 = Prover::new_link_secret().unwrap();
            let credential_values_1 = helpers::gvt_credential_values();

            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values_1 = helpers::blind_credential_values(&link_secret_1);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values_1,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_1 = 1;
            let (
                mut credential_signature_1,
                signature_correctness_proof,
                mut witness_1,
                rev_reg_delta,
            ) = Issuer::sign_credential_with_revoc(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values_1,
                &credential_pub_key,
                &credential_priv_key,
                rev_idx_1,
                max_cred_num,
                issuance_by_default,
                &mut rev_reg,
                &rev_key_priv,
            )
            .unwrap();
            let mut full_delta = rev_reg_delta.unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_1,
                &credential_values_1
                    .merge(&blind_credential_values_1)
                    .unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_1),
            )
            .unwrap();

            // 5. Issuer issues second credential
            let link_secret_2 = Prover::new_link_secret().unwrap();
            let credential_values_2 = helpers::gvt_credential_values();

            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values_2 = helpers::blind_credential_values(&link_secret_2);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values_2,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_2 = 2;
            let (mut credential_signature_2, signature_correctness_proof, witness_2, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values_2,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_2,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();

            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_2,
                &credential_values_2
                    .merge(&blind_credential_values_2)
                    .unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_2),
            )
            .unwrap();

            // 6. Issuer issues third credential
            let link_secret_3 = Prover::new_link_secret().unwrap();
            let credential_values_3 = helpers::gvt_credential_values();

            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values_3 = helpers::blind_credential_values(&link_secret_3);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values_3,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_3 = 3;
            let (mut credential_signature_3, signature_correctness_proof, witness_3, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values_3,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_3,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_3,
                &credential_values_3
                    .merge(&blind_credential_values_3)
                    .unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_3),
            )
            .unwrap();

            // 7. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 8. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // Proving first credential
            // 9. Prover updates witness_1
            witness_1
                .update(rev_idx_1, max_cred_num, &full_delta, &simple_tail_accessor)
                .unwrap();

            // 10. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature_1,
                    &credential_values_1
                        .merge(&blind_credential_values_1)
                        .unwrap(),
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness_1),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 11. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_for_three_credentials_revoke_first_proving_third() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Issuer issues first credential
            let link_secret_1 = Prover::new_link_secret().unwrap();
            let credential_values_1 = helpers::gvt_credential_values();

            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values_1 = helpers::blind_credential_values(&link_secret_1);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values_1,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_1 = 1;
            let (mut credential_signature_1, signature_correctness_proof, witness_1, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values_1,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_1,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();
            let mut full_delta = rev_reg_delta.unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_1,
                &credential_values_1
                    .merge(&blind_credential_values_1)
                    .unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_1),
            )
            .unwrap();

            // 5. Issuer issues second credential
            let link_secret_2 = Prover::new_link_secret().unwrap();
            let credential_values_2 = helpers::gvt_credential_values();
            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values_2 = helpers::blind_credential_values(&link_secret_2);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values_2,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx_2 = 2;
            let (mut credential_signature_2, signature_correctness_proof, witness_2, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values_2,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_2,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_2,
                &credential_values_2
                    .merge(&blind_credential_values_2)
                    .unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_2),
            )
            .unwrap();

            // 6. Issuer issues third credential
            let link_secret_3 = Prover::new_link_secret().unwrap();
            let credential_values_3 = helpers::gvt_credential_values();
            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values_3 = helpers::blind_credential_values(&link_secret_3);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values_3,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_3 = 3;
            let (
                mut credential_signature_3,
                signature_correctness_proof,
                mut witness_3,
                rev_reg_delta,
            ) = Issuer::sign_credential_with_revoc(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values_3,
                &credential_pub_key,
                &credential_priv_key,
                rev_idx_3,
                max_cred_num,
                issuance_by_default,
                &mut rev_reg,
                &rev_key_priv,
            )
            .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();
            let mut delta_for_third = RevocationRegistryDelta::from(&rev_reg);

            Prover::process_credential_signature(
                &mut credential_signature_3,
                &credential_values_3
                    .merge(&blind_credential_values_3)
                    .unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_3),
            )
            .unwrap();

            // 7. Issuer revokes first credential
            let rev_reg_delta = Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx_1,
                &credential_pub_key,
                &rev_key_priv,
            )
            .unwrap();
            full_delta.merge(&rev_reg_delta).unwrap();
            delta_for_third.merge(&rev_reg_delta).unwrap();

            // 8. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 9. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // Proving third credential
            // 10. Prover updates witness_1
            witness_3
                .update(
                    rev_idx_3,
                    max_cred_num,
                    &delta_for_third,
                    &simple_tail_accessor,
                )
                .unwrap();

            // 11. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature_3,
                    &credential_values_3
                        .merge(&blind_credential_values_3)
                        .unwrap(),
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness_3),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_for_three_credentials_revoke_third_proving_first() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Issuer issues first credential
            let link_secret_1 = Prover::new_link_secret().unwrap();
            let credential_values_1 = helpers::gvt_credential_values();
            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values_1 = helpers::blind_credential_values(&link_secret_1);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values_1,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_1 = 1;
            let (
                mut credential_signature_1,
                signature_correctness_proof,
                mut witness_1,
                rev_reg_delta,
            ) = Issuer::sign_credential_with_revoc(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values_1,
                &credential_pub_key,
                &credential_priv_key,
                rev_idx_1,
                max_cred_num,
                issuance_by_default,
                &mut rev_reg,
                &rev_key_priv,
            )
            .unwrap();

            let mut full_delta = rev_reg_delta.unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_1,
                &credential_values_1
                    .merge(&blind_credential_values_1)
                    .unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_1),
            )
            .unwrap();

            // 5. Issuer issues second credential
            let link_secret_2 = Prover::new_link_secret().unwrap();
            let credential_values_2 = helpers::gvt_credential_values();
            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values_2 = helpers::blind_credential_values(&link_secret_2);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values_2,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_2 = 2;
            let (mut credential_signature_2, signature_correctness_proof, witness_2, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values_2,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_2,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_2,
                &credential_values_2
                    .merge(&blind_credential_values_2)
                    .unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_2),
            )
            .unwrap();

            // 6. Issuer issues third credential
            let link_secret_3 = Prover::new_link_secret().unwrap();
            let credential_values_3 = helpers::gvt_credential_values();
            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values_3 = helpers::blind_credential_values(&link_secret_3);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values_3,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_3 = 3;
            let (mut credential_signature_3, signature_correctness_proof, witness_3, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values_3,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_3,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_3,
                &credential_values_3
                    .merge(&blind_credential_values_3)
                    .unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_3),
            )
            .unwrap();

            // 7. Issuer revokes third credential
            let rev_reg_delta = Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx_3,
                &credential_pub_key,
                &rev_key_priv,
            )
            .unwrap();
            full_delta.merge(&rev_reg_delta).unwrap();

            // 8. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 9. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // Proving first credential
            // 10. Prover updates witness_1
            witness_1
                .update(rev_idx_1, max_cred_num, &full_delta, &simple_tail_accessor)
                .unwrap();

            // 11. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature_1,
                    &credential_values_1
                        .merge(&blind_credential_values_1)
                        .unwrap(),
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness_1),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_for_three_credentials_revoke_first_and_third_proving_second(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, mut rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

            // 4. Issuer issues first credential
            let link_secret_1 = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();
            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values = helpers::blind_credential_values(&link_secret_1);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_1 = 1;
            let (mut credential_signature_1, signature_correctness_proof, witness_1, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_1,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();
            let mut full_delta = rev_reg_delta.unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_1,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_1),
            )
            .unwrap();

            // 5. Issuer issues second credential
            let link_secret_2 = Prover::new_link_secret().unwrap();
            let credential_values_2 = helpers::gvt_credential_values();
            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values_2 = helpers::blind_credential_values(&link_secret_2);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values_2,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_2 = 2;
            let (
                mut credential_signature_2,
                signature_correctness_proof,
                mut witness_2,
                rev_reg_delta,
            ) = Issuer::sign_credential_with_revoc(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values_2,
                &credential_pub_key,
                &credential_priv_key,
                rev_idx_2,
                max_cred_num,
                issuance_by_default,
                &mut rev_reg,
                &rev_key_priv,
            )
            .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();
            let mut delta_for_second = RevocationRegistryDelta::from(&rev_reg);

            Prover::process_credential_signature(
                &mut credential_signature_2,
                &credential_values_2
                    .merge(&blind_credential_values_2)
                    .unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_2),
            )
            .unwrap();

            // 6. Issuer issues third credential
            let link_secret_3 = Prover::new_link_secret().unwrap();
            let credential_values_3 = helpers::gvt_credential_values();
            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values_3 = helpers::blind_credential_values(&link_secret_3);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values_3,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_3 = 3;
            let (mut credential_signature_3, signature_correctness_proof, witness_3, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values_3,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_3,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();
            let rev_reg_delta = rev_reg_delta.unwrap();
            full_delta.merge(&rev_reg_delta).unwrap();
            delta_for_second.merge(&rev_reg_delta).unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_3,
                &credential_values_3
                    .merge(&blind_credential_values_3)
                    .unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_3),
            )
            .unwrap();

            // 7. Issuer revokes first credential
            let rev_reg_delta = Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx_1,
                &credential_pub_key,
                &rev_key_priv,
            )
            .unwrap();
            full_delta.merge(&rev_reg_delta).unwrap();
            delta_for_second.merge(&rev_reg_delta).unwrap();

            // 8. Issuer revokes third credential
            let rev_reg_delta = Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx_3,
                &credential_pub_key,
                &rev_key_priv,
            )
            .unwrap();
            full_delta.merge(&rev_reg_delta).unwrap();
            delta_for_second.merge(&rev_reg_delta).unwrap();

            // 9. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 10. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // Proving second credential
            // 11. Prover updates witness_2
            witness_2
                .update(
                    rev_idx_2,
                    max_cred_num,
                    &delta_for_second,
                    &simple_tail_accessor,
                )
                .unwrap();

            // 12. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature_2,
                    &credential_values_2
                        .merge(&blind_credential_values_2)
                        .unwrap(),
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness_2),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 13. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_revocation_proof_for_two_credentials_proving_first_with_outdated_witness(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, _rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            // 4. Issuer issues first credential
            let link_secret_1 = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();
            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values = helpers::blind_credential_values(&link_secret_1);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_1 = 1;
            let (mut credential_signature_1, signature_correctness_proof, witness_1, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_1,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();
            let mut full_delta = rev_reg_delta.unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_1,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_1),
            )
            .unwrap();

            // 5. Issuer issues second credential
            let link_secret_2 = Prover::new_link_secret().unwrap();
            let credential_values_2 = helpers::gvt_credential_values();
            let credential_nonce = new_nonce().unwrap();
            let blind_credential_values_2 = helpers::blind_credential_values(&link_secret_2);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values_2,
                &credential_nonce,
            )
            .unwrap();
            let credential_issuance_nonce = new_nonce().unwrap();
            let rev_idx_2 = 2;
            let (mut credential_signature_2, signature_correctness_proof, witness_2, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values_2,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx_2,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();

            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            Prover::process_credential_signature(
                &mut credential_signature_2,
                &credential_values_2
                    .merge(&blind_credential_values_2)
                    .unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness_2),
            )
            .unwrap();

            // 7. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 8. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // Proving first credential
            // 9. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature_1,
                    &credential_values.merge(&blind_credential_values).unwrap(),
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness_1),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 10. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_proof_created_before_credential_revoked() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, _rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            // 4. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, witness, _rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();

            // 8. Prover processes credential signature
            let prover_credential_values =
                credential_values.merge(&blind_credential_values).unwrap();
            Prover::process_credential_signature(
                &mut credential_signature,
                &prover_credential_values,
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 9. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 10. Verifier create sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 11. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &prover_credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 12. Issuer revokes credential used for proof building
            Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx,
                &credential_pub_key,
                &rev_key_priv,
            )
            .unwrap();

            // 13. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_proof_created_after_credential_revoked() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, _rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            // 4. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, witness, _rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();

            // 10. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 11. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 12. Verifier create sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 13. Issuer revokes credential
            Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx,
                &credential_pub_key,
                &rev_key_priv,
            )
            .unwrap();

            // 14. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values.merge(&blind_credential_values).unwrap(),
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 15. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_proof_created_after_credential_revoked_issuance_by_default() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let issuance_by_default = true;
            let (rev_key_pub, rev_key_priv, mut rev_reg, _rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            // 4. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, witness, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();
            assert!(rev_reg_delta.is_none());

            // 10. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 11. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 12. Verifier create sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 13. Issuer revokes credential
            Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx,
                &credential_pub_key,
                &rev_key_priv,
            )
            .unwrap();

            // 14. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values.merge(&blind_credential_values).unwrap(),
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 15. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_unrevoked_credential() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 4. Issuer creates revocation registry with IssuanceOnDemand type
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, _rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            // 4. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, witness, _rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();

            // 9. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 11. Verifier creates proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 12. Prover builds proof
            let nonce = new_nonce().unwrap();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values.merge(&blind_credential_values).unwrap(),
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 13. Verifier verifies proof (Proof is valid)
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());

            // 14. Issuer revokes credential
            Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx,
                &credential_pub_key,
                &rev_key_priv,
            )
            .unwrap();

            // 15. Verifier verifies proof (Proof is not valid)
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());

            // 16. Issuer unrevokes credential
            Issuer::unrevoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx,
                &credential_pub_key,
                &rev_key_priv,
            )
            .unwrap();

            // 17. Verifier verifies proof (Proof is valid again)
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_update_revocation_registry() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 4. Issuer creates revocation registry with IssuanceOnDemand type
            let max_cred_num = 5;
            let issuance_by_default = false;
            let (rev_key_pub, rev_key_priv, mut rev_reg, _rev_tails_generator) =
                Issuer::new_revocation_registry_def(
                    &credential_pub_key,
                    max_cred_num,
                    issuance_by_default,
                )
                .unwrap();

            // 4. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let rev_idx = 1;
            let (mut credential_signature, signature_correctness_proof, witness, _rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    issuance_by_default,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();

            // 9. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // 11. Verifier creates proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 12. Prover builds proof
            let nonce = new_nonce().unwrap();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values.merge(&blind_credential_values).unwrap(),
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 13. Verifier verifies proof (Proof is valid)
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());

            // 14. Issuer revokes credential
            let mut revoked = BTreeSet::new();
            revoked.insert(rev_idx);
            Issuer::update_revocation_registry(
                &mut rev_reg,
                max_cred_num,
                BTreeSet::new(),
                revoked.clone(),
                &credential_pub_key,
                &rev_key_priv,
            )
            .unwrap();

            // 15. Verifier verifies proof (Proof is not valid)
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());

            // 16. Issuer unrevokes credential
            Issuer::update_revocation_registry(
                &mut rev_reg,
                max_cred_num,
                revoked.clone(),
                BTreeSet::new(),
                &credential_pub_key,
                &rev_key_priv,
            )
            .unwrap();

            // 17. Verifier verifies proof (Proof is valid again)
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        #[ignore]
        fn anoncreds_works_for_full_accumulator() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry for only 1 credential
            let max_cred_num = 1;
            let (_, rev_key_priv, mut rev_reg, _rev_tails_generator) =
                Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, false)
                    .unwrap();

            // 4. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &credential_pub_key,
                    &credential_key_correctness_proof,
                    &blind_credential_values,
                    &credential_nonce,
                )
                .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            Issuer::sign_credential_with_revoc(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
                1,
                max_cred_num,
                false,
                &mut rev_reg,
                &rev_key_priv,
            )
            .unwrap();

            // 8. Issuer creates and sign second credential values
            let _res = Issuer::sign_credential_with_revoc(
                &format!("{}2", PROVER_ID),
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &credential_pub_key,
                &credential_priv_key,
                2,
                max_cred_num,
                false,
                &mut rev_reg,
                &rev_key_priv,
            );
            // assert_eq!(
            //     ErrorKind::RevocationAccumulatorIsFull,
            //     res.unwrap_err().kind()
            // );
        }

        #[test]
        #[ignore]
        fn anoncreds_works_for_reissue_credential_with_same_index() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 1;
            let (rev_key_pub, rev_key_priv, mut rev_reg, _) =
                Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, false)
                    .unwrap();

            let rev_idx = 1;

            // FIRST Issue of credential
            // 4. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 5. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 6. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 8. Issuer creates and signs credential values
            let (mut credential_signature, signature_correctness_proof, witness, rev_reg_delta) =
                Issuer::sign_credential_with_revoc(
                    PROVER_ID,
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &credential_issuance_nonce,
                    &credential_values,
                    &credential_pub_key,
                    &credential_priv_key,
                    rev_idx,
                    max_cred_num,
                    false,
                    &mut rev_reg,
                    &rev_key_priv,
                )
                .unwrap();

            let mut full_delta = rev_reg_delta.unwrap();

            // 10. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();

            // Create proof by issued credential
            // 11. Verifier creates nonce
            let nonce = new_nonce().unwrap();

            // 12. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 13. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 14. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(true, proof_verifier.verify(&proof, &nonce).unwrap());

            // 15. Issuer revokes credential used for proof building
            let rev_reg_delta = Issuer::revoke_credential(
                &mut rev_reg,
                rev_idx,
                max_cred_num,
                &credential_pub_key,
                &rev_key_priv,
            )
            .unwrap();
            full_delta.merge(&rev_reg_delta).unwrap();

            // 16. Verifier verifies proof after revocation
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());

            // Reissue credential with different values but same rev_index

            // 16. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let new_credential_nonce = new_nonce().unwrap();

            // 17. Prover blinds master secret
            let (
                new_blinded_credential_secrets,
                new_credential_secrets_blinding_factors,
                new_blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &new_credential_nonce,
            )
            .unwrap();

            // 18. Prover creates nonce used Issuer to new credential issue
            let new_credential_issuance_nonce = new_nonce().unwrap();

            // 19. Issuer creates and signs new credential values
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_dec_known("name", "1139481716457488690172217916278103335")
                .unwrap();
            credential_values_builder
                .add_dec_known(
                    "sex",
                    "5944657099558967239210949258394887428692050081607692519917050011144233115103",
                )
                .unwrap();
            credential_values_builder
                .add_dec_known("age", "44")
                .unwrap();
            credential_values_builder
                .add_dec_known("height", "165")
                .unwrap();
            let credential_values = credential_values_builder.finalize().unwrap();

            let (
                mut new_credential_signature,
                new_signature_correctness_proof,
                witness,
                rev_reg_delta,
            ) = Issuer::sign_credential_with_revoc(
                PROVER_ID,
                &new_blinded_credential_secrets,
                &new_blinded_credential_secrets_correctness_proof,
                &new_credential_nonce,
                &new_credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
                rev_idx,
                max_cred_num,
                false,
                &mut rev_reg,
                &rev_key_priv,
            )
            .unwrap();
            full_delta.merge(&rev_reg_delta.unwrap()).unwrap();

            // 20. Prover processes new credential signature
            Prover::process_credential_signature(
                &mut new_credential_signature,
                &credential_values,
                &new_signature_correctness_proof,
                &new_credential_secrets_blinding_factors,
                &credential_pub_key,
                &new_credential_issuance_nonce,
                Some(&rev_key_pub),
                Some(&rev_reg),
                Some(&witness),
            )
            .unwrap();
            // 21. Prover creates proof using new credential
            let mut new_proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            new_proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &new_credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    Some(&rev_reg),
                    Some(&witness),
                )
                .unwrap();

            let new_proof = proof_builder.finalize(&nonce).unwrap();

            // 22. Verifier verifies proof created by new credential
            let mut new_proof_verifier = Verifier::new_proof_verifier().unwrap();
            new_proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert!(new_proof_verifier.verify(&new_proof, &nonce).unwrap());

            // 23. Verifier verifies proof created before the first credential had been revoked
            let mut old_proof_verifier = Verifier::new_proof_verifier().unwrap();
            old_proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    Some(&rev_key_pub),
                    Some(&rev_reg),
                )
                .unwrap();
            assert_eq!(false, old_proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_missed_process_credential_step() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &credential_pub_key,
                    &credential_key_correctness_proof,
                    &blind_credential_values,
                    &credential_nonce,
                )
                .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values
            let (credential_signature, _) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Verifier creates nonce and sub proof request
            let nonce = new_nonce().unwrap();
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 9. Prover creates proof by sub proof request not corresponded to verifier proof request
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values.merge(&blind_credential_values).unwrap(),
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 10. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_proof_created_with_wrong_link_secret() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values wrong keys
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Verifier creates nonce and sub proof request
            let nonce = new_nonce().unwrap();
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 10. Prover creates proof by sub proof request not corresponded to verifier proof request
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            let another_link_secret = Prover::new_link_secret().unwrap();
            let other_blind_credential_values =
                helpers::blind_credential_values(&another_link_secret);
            let credential_values = helpers::gvt_credential_values()
                .merge(&other_blind_credential_values)
                .unwrap();

            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            let proof = proof_builder.finalize(&nonce).unwrap();

            // 11. Verifier verifies proof
            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
        }

        #[test]
        fn anoncreds_works_for_used_different_nonce() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values wrong keys
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Verifier creates sub proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            // 10. Prover creates proof by sub proof request not corresponded to verifier proof request
            let nonce_for_proof_creation = new_nonce().unwrap();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values.merge(&blind_credential_values).unwrap(),
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();

            let proof = proof_builder.finalize(&nonce_for_proof_creation).unwrap();

            // 11. Verifier verifies proof
            let nonce_for_proof_verification = new_nonce().unwrap();

            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(
                false,
                proof_verifier
                    .verify(&proof, &nonce_for_proof_verification)
                    .unwrap()
            );
        }

        #[test]
        fn anoncreds_works_for_proof_not_correspond_to_verifier_proof_request() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Prover creates proof by sub proof request not corresponded to verifier proof request
            let sub_proof_request = helpers::gvt_sub_proof_request();

            let mut proof_builder = Prover::new_proof_builder().unwrap();
            let nonce = new_nonce().unwrap();

            proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request,
                    &credential_schema,
                    &non_credential_schema,
                    &credential_signature,
                    &credential_values.merge(&blind_credential_values).unwrap(),
                    &credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            let proof = proof_builder.finalize(&nonce).unwrap();

            // 10. Verifier verifies proof
            let xyz_credential_schema = helpers::xyz_credential_schema();
            let (xyz_credential_pub_key, _, _) =
                Issuer::new_credential_def(&xyz_credential_schema, &non_credential_schema, false)
                    .unwrap();
            let xyz_sub_proof_request = helpers::xyz_sub_proof_request();

            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
            proof_verifier
                .add_sub_proof_request(
                    &xyz_sub_proof_request,
                    &xyz_credential_schema,
                    &non_credential_schema,
                    &xyz_credential_pub_key,
                    None,
                    None,
                )
                .unwrap();
            let res = proof_verifier.verify(&proof, &nonce);
            assert_eq!(ErrorKind::ProofRejected, res.unwrap_err().kind());
        }

        #[test]
        fn issuer_create_keys_works_for_empty_credential_schema() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            let credential_schema = credential_schema_builder.finalize().unwrap();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let res = Issuer::new_credential_def(&credential_schema, &non_credential_schema, false);
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn issuer_create_revocation_registry_works_for_keys_without_revocation_part() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(without revocation part)
            let (credential_pub_key, _, _) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let res = Issuer::new_revocation_registry_def(&credential_pub_key, 5, false);
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        #[ignore]
        fn issuer_revoke_works_for_invalid_revocation_index() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition(with revocation keys)
            let (credential_pub_key, _, _) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, true)
                    .unwrap();

            // 3. Issuer creates revocation registry
            let max_cred_num = 5;
            let (_, rev_key_priv, mut rev_reg, _) =
                Issuer::new_revocation_registry_def(&credential_pub_key, max_cred_num, false)
                    .unwrap();

            // 4. Issuer tries revoke not not added index
            let rev_idx = 1;
            let _res = Issuer::revoke_credential(
                &mut rev_reg,
                max_cred_num,
                rev_idx,
                &credential_pub_key,
                &rev_key_priv,
            );
            // assert_eq!(
            //     ErrorKind::InvalidRevocationAccumulatorIndex,
            //     res.unwrap_err().kind()
            // );
        }

        #[test]
        fn issuer_sign_credential_works_for_credential_values_not_correspond_to_issuer_keys() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::xyz_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &credential_pub_key,
                    &credential_key_correctness_proof,
                    &blind_credential_values,
                    &credential_nonce,
                )
                .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values not correspondent to issuer keys

            // 8. Issuer signs wrong credential values
            let res = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            );

            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn proof_builder_add_sub_proof_works_for_credential_values_not_correspond_to_credential_schema(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Prover creates proof
            let mut proof_builder = Prover::new_proof_builder().unwrap();

            // Wrong credential values
            let credential_values = helpers::xyz_credential_values()
                .merge(&blind_credential_values)
                .unwrap();

            let sub_proof_request = helpers::gvt_sub_proof_request();

            let res = proof_builder.add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &credential_signature,
                &credential_values,
                &credential_pub_key,
                None,
                None,
            );

            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn proof_builder_add_sub_proof_works_for_credential_not_satisfy_to_sub_proof_request() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Verifier creates sub proof request
            let sub_proof_request = helpers::xyz_sub_proof_request();

            // 10. Prover creates proof by credential not correspondent to proof request
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();

            let res = proof_builder.add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &credential_pub_key,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn proof_builder_add_sub_proof_works_for_credential_not_contained_requested_attribute() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Verifier creates sub proof request
            let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
            sub_proof_request_builder
                .add_revealed_attr("status")
                .unwrap();
            let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

            // 10. Prover creates proof by credential not contained requested attribute
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();

            let res = proof_builder.add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &credential_pub_key,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn proof_builder_add_sub_proof_works_for_credential_not_satisfied_requested_predicate() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates and signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 8. Prover processes credential signature
            Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            )
            .unwrap();

            // 9. Verifier creates sub proof request
            let mut gvt_sub_proof_request_builder =
                Verifier::new_sub_proof_request_builder().unwrap();
            gvt_sub_proof_request_builder
                .add_revealed_attr("name")
                .unwrap();
            gvt_sub_proof_request_builder
                .add_predicate("age", "GE", 50)
                .unwrap();
            let sub_proof_request = gvt_sub_proof_request_builder.finalize().unwrap();

            // 10. Prover creates proof by credential value not satisfied predicate
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            proof_builder.add_common_attribute("master_secret").unwrap();

            let res = proof_builder.add_sub_proof_request(
                &sub_proof_request,
                &credential_schema,
                &non_credential_schema,
                &credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &credential_pub_key,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn proof_verifier_add_sub_proof_request_works_for_credential_schema_not_satisfied_to_sub_proof_request(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, _, _) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Verifier build proof verifier
            let sub_proof_request = helpers::gvt_sub_proof_request();
            let xyz_credential_schema = helpers::xyz_credential_schema();

            let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

            let res = proof_verifier.add_sub_proof_request(
                &sub_proof_request,
                &xyz_credential_schema,
                &non_credential_schema,
                &credential_pub_key,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn prover_blind_credential_secrets_works_for_key_correctness_proof_not_correspond_to_public_key(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();

            // 2. Issuer creates GVT credential definition
            let gvt_credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (gvt_credential_pub_key, _, _) =
                Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Issuer creates XYZ credential definition
            let xyz_credential_schema = helpers::xyz_credential_schema();
            let (_, _, xyz_credential_key_correctness_proof) =
                Issuer::new_credential_def(&xyz_credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let gvt_credential_nonce = new_nonce().unwrap();

            // 5. Prover blind master secret by gvt_public_key and xyz_key_correctness_proof
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let res = Prover::blind_credential_secrets(
                &gvt_credential_pub_key,
                &xyz_credential_key_correctness_proof,
                &blind_credential_values,
                &gvt_credential_nonce,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn issuer_sign_credential_works_for_prover_used_different_nonce_to_blind_credential_secrets(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            let other_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &credential_pub_key,
                    &credential_key_correctness_proof,
                    &blind_credential_values,
                    &other_nonce,
                )
                .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values

            // 8. Issuer signs credential values
            let res = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn issuer_sign_credential_works_for_keys_not_correspond_to_blinded_credential_secrets_correctness_proof(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates GVT credential definition
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (gvt_credential_pub_key, _, gvt_credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 2. Issuer creates XYZ credential definition
            let credential_schema = helpers::xyz_credential_schema();
            let (xyz_credential_pub_key, xyz_credential_priv_key, _) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret by GVT key
            let gvt_blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &gvt_credential_pub_key,
                    &gvt_credential_key_correctness_proof,
                    &gvt_blind_credential_values,
                    &credential_nonce,
                )
                .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values
            let xyz_credential_values = helpers::xyz_credential_values();

            // 8. Issuer signs XYZ credential values for Prover
            let res = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &xyz_credential_values,
                &xyz_credential_pub_key,
                &xyz_credential_priv_key,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn issuer_sign_credential_works_for_blinded_credential_secrets_not_correspond_to_blinded_credential_secrets_correctness_proof(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates GVT credential definition
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 2. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 3. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 4. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (_, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &credential_pub_key,
                    &credential_key_correctness_proof,
                    &blind_credential_values,
                    &credential_nonce,
                )
                .unwrap();

            // 5. Prover blinds master secret second time
            let (blinded_credential_secrets, _, _) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values

            // 8. Issuer signs credential values for Prover
            let res = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn prover_process_credential_signature_works_for_issuer_used_different_nonce() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let different_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values

            // 8. Issuer signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &different_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 9. Prover processes credential signature
            let res = Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn prover_process_credential_signature_works_for_credential_signature_not_correspond_to_signature_correctness_proof(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            let different_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values

            // 8. Issuer signs credential values
            let (mut credential_signature, _) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &different_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 9. Issuer signs credential values second time
            let (_, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &different_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 10. Prover processes credential signature
            let res = Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn prover_process_credential_signature_works_for_credential_secrets_blinding_factors_not_correspond_to_signature(
        ) {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
                Prover::blind_credential_secrets(
                    &credential_pub_key,
                    &credential_key_correctness_proof,
                    &blind_credential_values,
                    &credential_nonce,
                )
                .unwrap();

            // 6. Prover blinds master secret second time
            let (_, credential_secrets_blinding_factors, _) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 7. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 8. Issuer creates credential values

            // 9. Issuer signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            // 10. Prover processes credential signature
            let res = Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &credential_issuance_nonce,
                None,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }

        #[test]
        fn prover_process_credential_signature_works_for_use_different_nonce() {
            // HLCryptoDefaultLogger::init(None).ok();

            // 1. Issuer creates credential schema
            let credential_schema = helpers::gvt_credential_schema();
            let non_credential_schema = helpers::non_credential_schema();

            // 2. Issuer creates credential definition
            let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
                Issuer::new_credential_def(&credential_schema, &non_credential_schema, false)
                    .unwrap();

            // 3. Prover creates master secret
            let link_secret = Prover::new_link_secret().unwrap();
            let credential_values = helpers::gvt_credential_values();

            // 4. Issuer creates nonce used by Prover to create correctness proof for blinded secrets
            let credential_nonce = new_nonce().unwrap();

            // 5. Prover blinds master secret
            let blind_credential_values = helpers::blind_credential_values(&link_secret);
            let (
                blinded_credential_secrets,
                credential_secrets_blinding_factors,
                blinded_credential_secrets_correctness_proof,
            ) = Prover::blind_credential_secrets(
                &credential_pub_key,
                &credential_key_correctness_proof,
                &blind_credential_values,
                &credential_nonce,
            )
            .unwrap();

            // 6. Prover creates nonce used by Issuer to create correctness proof for signature
            let credential_issuance_nonce = new_nonce().unwrap();

            // 7. Issuer creates credential values

            // 8. Issuer signs credential values
            let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(
                PROVER_ID,
                &blinded_credential_secrets,
                &blinded_credential_secrets_correctness_proof,
                &credential_nonce,
                &credential_issuance_nonce,
                &credential_values,
                &credential_pub_key,
                &credential_priv_key,
            )
            .unwrap();

            let other_nonce = new_nonce().unwrap();

            // 9. Prover processes credential signature
            let res = Prover::process_credential_signature(
                &mut credential_signature,
                &credential_values.merge(&blind_credential_values).unwrap(),
                &signature_correctness_proof,
                &credential_secrets_blinding_factors,
                &credential_pub_key,
                &other_nonce,
                None,
                None,
                None,
            );
            assert_eq!(ErrorKind::InvalidState, res.unwrap_err().kind());
        }
    }

    mod helpers {
        use super::*;

        pub fn blind_credential_values(link_secret: &LinkSecret) -> CredentialValues {
            let mut credential_values_builder = CredentialValuesBuilder::new().unwrap();
            credential_values_builder
                .add_value_hidden("master_secret", link_secret.as_ref())
                .unwrap();
            credential_values_builder.finalize().unwrap()
        }

        pub fn gvt_credential_schema() -> CredentialSchema {
            let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            credential_schema_builder.add_attr("name").unwrap();
            credential_schema_builder.add_attr("sex").unwrap();
            credential_schema_builder.add_attr("age").unwrap();
            credential_schema_builder.add_attr("height").unwrap();
            credential_schema_builder.finalize().unwrap()
        }

        pub fn xyz_credential_schema() -> CredentialSchema {
            let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            credential_schema_builder.add_attr("status").unwrap();
            credential_schema_builder.add_attr("period").unwrap();
            credential_schema_builder.finalize().unwrap()
        }

        pub fn pqr_credential_schema() -> CredentialSchema {
            let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
            credential_schema_builder.add_attr("name").unwrap();
            credential_schema_builder.add_attr("address").unwrap();
            credential_schema_builder.finalize().unwrap()
        }

        pub fn non_credential_schema() -> NonCredentialSchema {
            let mut non_credential_schema_builder =
                Issuer::new_non_credential_schema_builder().unwrap();
            non_credential_schema_builder
                .add_attr("master_secret")
                .unwrap();
            non_credential_schema_builder.finalize().unwrap()
        }

        pub fn gvt_credential_values() -> CredentialValues {
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_dec_known("name", "1139481716457488690172217916278103335")
                .unwrap();
            credential_values_builder
                .add_dec_known(
                    "sex",
                    "5944657099558967239210949258394887428692050081607692519917050011144233115103",
                )
                .unwrap();
            credential_values_builder
                .add_dec_known("age", "28")
                .unwrap();
            credential_values_builder
                .add_dec_known("height", "175")
                .unwrap();
            credential_values_builder.finalize().unwrap()
        }

        pub fn xyz_credential_values() -> CredentialValues {
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_dec_known("status", "51792877103171595686471452153480627530895")
                .unwrap();
            credential_values_builder
                .add_dec_known("period", "8")
                .unwrap();
            credential_values_builder.finalize().unwrap()
        }

        pub fn pqr_credential_values() -> CredentialValues {
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_dec_known("name", "1139481716457488690172217916278103335")
                .unwrap();
            credential_values_builder
                .add_dec_known("address", "51792877103171595686471452153480627530891")
                .unwrap();
            credential_values_builder.finalize().unwrap()
        }

        pub fn pqr_credential_values_1() -> CredentialValues {
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            credential_values_builder
                .add_dec_known("name", "7181645748869017221791627810333511394")
                .unwrap();
            credential_values_builder
                .add_dec_known("address", "51792877103171595686471452153480627530891")
                .unwrap();
            credential_values_builder.finalize().unwrap()
        }

        pub fn gvt_sub_proof_request() -> SubProofRequest {
            let mut gvt_sub_proof_request_builder =
                Verifier::new_sub_proof_request_builder().unwrap();
            gvt_sub_proof_request_builder
                .add_revealed_attr("name")
                .unwrap();
            gvt_sub_proof_request_builder
                .add_predicate("age", "GE", 18)
                .unwrap();
            gvt_sub_proof_request_builder.finalize().unwrap()
        }

        pub fn xyz_sub_proof_request() -> SubProofRequest {
            let mut xyz_sub_proof_request_builder =
                Verifier::new_sub_proof_request_builder().unwrap();
            xyz_sub_proof_request_builder
                .add_revealed_attr("status")
                .unwrap();
            xyz_sub_proof_request_builder
                .add_predicate("period", "GE", 4)
                .unwrap();
            xyz_sub_proof_request_builder.finalize().unwrap()
        }

        pub fn pqr_sub_proof_request() -> SubProofRequest {
            let mut pqr_sub_proof_request_builder =
                Verifier::new_sub_proof_request_builder().unwrap();
            pqr_sub_proof_request_builder
                .add_revealed_attr("address")
                .unwrap();
            pqr_sub_proof_request_builder.finalize().unwrap()
        }

        pub fn gvt_sub_proof_request_1() -> SubProofRequest {
            let mut gvt_sub_proof_request_builder =
                Verifier::new_sub_proof_request_builder().unwrap();
            gvt_sub_proof_request_builder
                .add_revealed_attr("sex")
                .unwrap();
            gvt_sub_proof_request_builder.finalize().unwrap()
        }
    }
}
