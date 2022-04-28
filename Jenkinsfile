node {
    files= ['deploy.yml']
    
    withCredentials([usernamePassword(credentialsId: 'prisma_cloud', passwordVariable: 'PC_PASS', usernameVariable: 'PC_USER')]) {
	    echo "Got $PC_USER and $PC_PASS"
            PC_TOKEN = sh(script:"curl -s -k -H 'Content-Type: application/json' -H 'accept: application/json' --data '{\"username\":\"$PC_USER\", \"password\":\"$PC_PASS\"}' https://${AppStack}/login | jq --raw-output .token", returnStdout:true).trim()
	    echo "Got PC_TOKEN"
    }

    stage('Clone repository') {
        checkout scm
    }


    stage('Check image Git dependencies has no vulnerabilities') {
        try {
            withCredentials([usernamePassword(credentialsId: 'twistlock_creds', passwordVariable: 'TL_PASS', usernameVariable: 'TL_USER')]) {
                sh('chmod +x files/checkGit.sh && ./files/checkGit.sh')
            }
        } catch (err) {
            echo err.getMessage()
            echo "Error detected"
			throw RuntimeException("Build failed for some specific reason!")
        }
    }

    //$PC_USER,$PC_PASS,$PC_CONSOLE when Galileo is released. 
    stage('Apply security policies (Policy-as-Code) for evilpetclinic') {
        withCredentials([usernamePassword(credentialsId: 'twistlock_creds', passwordVariable: 'TL_PASS', usernameVariable: 'TL_USER')]) {
            sh('chmod +x files/addPolicies.sh && ./files/addPolicies.sh')
        }
    }

    //$PC_USER,$PC_PASS,$PC_CONSOLE when Galileo is released. 
    stage('Download latest twistcli') {
        withCredentials([usernamePassword(credentialsId: 'prisma_cloud', passwordVariable: 'PC_PASS', usernameVariable: 'PC_USER')]) {
            sh 'curl -k -u $PC_USER:$PC_PASS --output ./twistcli https://$PC_CONSOLE/api/v1/util/twistcli'
            sh 'sudo chmod a+x ./twistcli'
        }
    }

    stage('Scan image with twistcli') {
        try {
	    // Scan the image
	    //sh 'docker pull solalraveh/evilpetclinic:latest'
            //withCredentials([usernamePassword(credentialsId: 'twistlock_creds', passwordVariable: 'TL_PASS', usernameVariable: 'TL_USER')]) {
            //    sh 'curl -k -u $TL_USER:$TL_PASS --output ./twistcli https://$TL_CONSOLE/api/v1/util/twistcli'
            //    sh 'sudo chmod a+x ./twistcli'
            //    sh "./twistcli images scan --u $TL_USER --p $TL_PASS --address https://$TL_CONSOLE --details solalraveh/evilpetclinic:latest"
            //}
            prismaCloudScanImage ca: '',
            cert: '',
            dockerAddress: 'unix:///var/run/docker.sock',
            // dockerAddress: 'tcp://192.168.10.60:2375',
            image: 'solalraveh/evilpetclinic:latest',
            key: '',
            logLevel: 'info',
            podmanPath: '',
            project: '',
            resultsFile: 'prisma-cloud-scan-results.json',
            ignoreImageBuildTime:true
	    prismaCloudPublish resultsFilePattern: 'prisma-cloud-scan-results.json'
        } catch (err) {
	    prismaCloudPublish resultsFilePattern: 'prisma-cloud-scan-results.json'
            echo err.getMessage()
            echo "Error detected"
	    throw RuntimeException("Build failed for some specific reason!")
        }
    }

	
stage('Checkov') {
	try {
             //response = sh(script:"checkov --file files/deploy.yml", returnStdout:true).trim() // -o junitxml > result.xml || true"
	     withCredentials([
            	string(
              		credentialsId: 'bc-api-key',
              		variable: 'BC_API')
             ]) {
		response = sh(script:"checkov --file files/deploy.yml --bc-api-key $BC_API --repo-id gbaileymcewan/gbaileymcewa1430-shiftleftdemo -b main -o junitxml > result.xml || true", returnStdout:true).trim() // -o junitxml > result.xml || true"
             }
		
	     //print "${response}"
	     response = sh(script:"cat result.xml", returnStdout:true)
	     print "${response}"
             junit skipPublishingChecks: true, testResults: "result.xml"
	}
	catch (err) {
            echo err.getMessage()
            echo "Error detected"
	}
}

//    files.each { item ->
//        stage("Scan IaC file ${item} with twistcli") {
//            try {
//                withCredentials([usernamePassword(credentialsId: 'prisma_cloud', passwordVariable: 'PC_PASS', usernameVariable: 'PC_USER')]) {
//                    //sh "./twistcli iac scan --u $PC_USER --p $PC_PASS --asset-name "Jenkins IaC" --tags env:jenkins --compliance-threshold high --address https://$PC_CONSOLE --files files/${item}"
//                    sh "./twistcli iac scan --u $PC_USER --p $PC_PASS --type k8s --asset-name evilpetclinic --compliance-threshold medium --address https://$PC_CONSOLE files/${item}"
//                }
//            } catch (err) {
//                echo err.getMessage()
//                echo "Error detected"
//				throw RuntimeException("Build failed for some specific reason!")
//            }
//	    }
//    }

    stage('Deploy evilpetclinic') {
        sh 'kubectl create ns evil --dry-run -o yaml | kubectl apply -f -'
        sh 'kubectl delete --ignore-not-found=true -f files/deploy.yml -n evil'
        sh 'kubectl apply -f files/deploy.yml -n evil'
        sh 'sleep 10'
    }

    stage('Run bad Runtime attacks') {
        sh('chmod +x files/runtime_attacks.sh && ./files/runtime_attacks.sh')
    }

    stage('Run bad HTTP stuff for WAAS to catch') {
        sh('chmod +x files/waas_attacks.sh && ./files/waas_attacks.sh')
    }
    post {
        always {
            // The post section lets you run the publish step regardless of the scan results
            prismaCloudPublish resultsFilePattern: 'prisma-cloud-scan-results.json'
        }
    }
    options {
        preserveStashes()
        timestamps()
        ansiColor('xterm')
    }
}
